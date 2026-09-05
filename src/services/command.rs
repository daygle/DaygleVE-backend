//! Host command routing and the broker privilege boundary.
//!
//! When `DAYGLEVE_BROKER_SOCKET` is set, privileged operations are sent to the
//! root-owned `daygleve-broker` over its authenticated Unix socket. The direct
//! command path remains available only when the broker is not configured, which
//! keeps local development and unit tests usable without a Linux appliance.

use std::path::Path;
use std::time::Duration;

use tokio::process::Command;

use crate::error::{ApiResult, AppError};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

fn program_path(program: &str) -> Option<&'static str> {
    Some(match program {
        "bridge" => "/usr/sbin/bridge",
        "ip" => "/usr/sbin/ip",
        "lxc-cgroup" => "/usr/bin/lxc-cgroup",
        "lxc-create" => "/usr/bin/lxc-create",
        "lxc-destroy" => "/usr/bin/lxc-destroy",
        "lxc-freeze" => "/usr/bin/lxc-freeze",
        "lxc-info" => "/usr/bin/lxc-info",
        "lxc-ls" => "/usr/bin/lxc-ls",
        "lxc-start" => "/usr/bin/lxc-start",
        "lxc-stop" => "/usr/bin/lxc-stop",
        "lxc-unfreeze" => "/usr/bin/lxc-unfreeze",
        "mount" => "/usr/bin/mount",
        "umount" => "/usr/bin/umount",
        "virsh" => "/usr/bin/virsh",
        "zfs" => "/usr/sbin/zfs",
        "zpool" => "/usr/sbin/zpool",
        _ => return None,
    })
}

fn validate_program(program: &str) -> ApiResult<&'static str> {
    program_path(program)
        .ok_or_else(|| AppError::internal(format!("host program `{program}` is not permitted")))
}

fn command_for(executable: &str) -> Command {
    let mut command = Command::new(executable);
    command.env_clear();
    command.env(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    command.env("LC_ALL", "C");
    command
}

#[cfg(unix)]
fn broker_client() -> Option<crate::broker::client::BrokerClient> {
    std::env::var("DAYGLEVE_BROKER_SOCKET")
        .ok()
        .filter(|path| !path.is_empty())
        .map(std::path::PathBuf::from)
        .map(crate::broker::client::BrokerClient::new)
}

#[cfg(unix)]
fn broker_error(error: impl std::fmt::Display) -> AppError {
    AppError::hypervisor(format!("root-owned broker request failed: {error}"))
}

/// Execute an allowlisted command through the broker when configured, otherwise
/// use the fixed-path direct development path.
pub async fn run(program: &str, args: &[&str]) -> ApiResult<String> {
    let executable = validate_program(program)?;
    #[cfg(unix)]
    if let Some(client) = broker_client() {
        return client
            .exec(program, args)
            .await
            .map(|output| output.stdout)
            .map_err(broker_error);
    }

    let output = run_with_timeout(executable, args, COMMAND_TIMEOUT).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AppError::hypervisor(format!(
            "`{program} {}` failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub async fn run_ok(program: &str, args: &[&str]) -> ApiResult<()> {
    run(program, args).await.map(|_| ())
}

/// Like [`run`], but a missing executable is treated as an unavailable optional
/// host feature. A configured broker is never bypassed if it is unavailable.
pub async fn run_optional(program: &str, args: &[&str]) -> ApiResult<Option<String>> {
    validate_program(program)?;
    #[cfg(unix)]
    if let Some(client) = broker_client() {
        return match client.exec(program, args).await {
            Ok(output) => Ok(Some(output.stdout)),
            Err(crate::broker::client::BrokerError::SpawnNotFound(_)) => Ok(None),
            Err(error) => Err(broker_error(error)),
        };
    }

    let executable = validate_program(program)?;
    match tokio::time::timeout(
        COMMAND_TIMEOUT,
        command_for(executable)
            .kill_on_drop(true)
            .args(args)
            .output(),
    )
    .await
    {
        Ok(Ok(output)) if output.status.success() => {
            Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
        }
        Ok(Ok(output)) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(AppError::hypervisor(format!(
                "`{program} {}` failed: {}",
                args.join(" "),
                stderr.trim()
            )))
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Ok(Err(e)) => Err(AppError::hypervisor(format!(
            "failed to run `{program}`: {e}"
        ))),
        Err(_) => Err(AppError::hypervisor(format!(
            "`{program}` timed out after {} seconds",
            COMMAND_TIMEOUT.as_secs()
        ))),
    }
}

/// Build a direct command for the two streaming helpers' development fallback.
/// Callers must use [`stream_to_file`] / [`stream_from_file`] for privileged
/// backup paths; this function is not a broker bypass.
pub(crate) fn new(program: &str) -> ApiResult<Command> {
    if broker_configured() {
        return Err(AppError::internal(
            "direct host command construction is disabled while the broker is configured",
        ));
    }
    Ok(command_for(validate_program(program)?))
}

fn broker_configured() -> bool {
    std::env::var("DAYGLEVE_BROKER_SOCKET")
        .ok()
        .is_some_and(|path| !path.is_empty())
}

/// Stream an allowlisted command's stdout into a file. Backup send operations
/// use this so `zfs send` never executes in the backend when the broker is on.
pub async fn stream_to_file(program: &str, args: &[&str], path: &Path) -> ApiResult<u64> {
    #[cfg(unix)]
    if let Some(client) = broker_client() {
        let mut file = tokio::fs::File::create(path)
            .await
            .map_err(|e| AppError::internal(format!("create {}: {e}", path.display())))?;
        client
            .exec_streamed(program, args, Option::<tokio::io::Empty>::None, &mut file)
            .await
            .map_err(broker_error)?;
        let metadata = file
            .metadata()
            .await
            .map_err(|e| AppError::internal(format!("stat {}: {e}", path.display())))?;
        return Ok(metadata.len());
    }

    let mut child = new(program)?
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| AppError::hypervisor(format!("failed to start {program}: {e}")))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| AppError::internal("stream stdout was not captured"))?;
    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|e| AppError::internal(format!("create {}: {e}", path.display())))?;
    let copied = tokio::time::timeout(
        Duration::from_secs(24 * 60 * 60),
        tokio::io::copy(&mut stdout, &mut file),
    )
    .await
    .map_err(|_| AppError::hypervisor(format!("{program} stream timed out")))?
    .map_err(|e| AppError::internal(format!("write stream: {e}")))?;
    use tokio::io::AsyncWriteExt;
    file.flush()
        .await
        .map_err(|e| AppError::internal(format!("flush stream: {e}")))?;
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| AppError::hypervisor(format!("wait for {program}: {e}")))?;
    if !output.status.success() {
        let _ = tokio::fs::remove_file(path).await;
        return Err(AppError::hypervisor(format!(
            "{program} stream failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(copied)
}

/// Stream a file into an allowlisted command's stdin. Backup restore uses this
/// for `zfs receive`.
pub async fn stream_from_file(program: &str, args: &[&str], path: &Path) -> ApiResult<()> {
    #[cfg(unix)]
    if let Some(client) = broker_client() {
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|e| AppError::internal(format!("open {}: {e}", path.display())))?;
        let mut sink = tokio::io::sink();
        client
            .exec_streamed(program, args, Some(file), &mut sink)
            .await
            .map_err(broker_error)?;
        return Ok(());
    }

    let mut child = new(program)?
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| AppError::hypervisor(format!("failed to start {program}: {e}")))?;
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| AppError::internal("stream stdin was not captured"))?;
    let mut source = tokio::fs::File::open(path)
        .await
        .map_err(|e| AppError::internal(format!("open {}: {e}", path.display())))?;
    tokio::time::timeout(
        Duration::from_secs(24 * 60 * 60),
        tokio::io::copy(&mut source, &mut input),
    )
    .await
    .map_err(|_| AppError::hypervisor(format!("{program} stream timed out")))?
    .map_err(|e| AppError::internal(format!("read stream: {e}")))?;
    drop(input);
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| AppError::hypervisor(format!("wait for {program}: {e}")))?;
    if !output.status.success() {
        return Err(AppError::hypervisor(format!(
            "{program} stream failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Delegate a constrained vfio sysfs write when the broker is enabled.
pub async fn pci_write(kind: crate::broker::PciWriteKind, address: &str) -> ApiResult<()> {
    crate::broker::validate_pci_address(address).map_err(AppError::validation)?;
    #[cfg(unix)]
    if let Some(client) = broker_client() {
        return client.pci_write(kind, address).await.map_err(broker_error);
    }
    let (path, value) = crate::broker::pci_write_target(kind, address);
    tokio::fs::write(&path, value.as_bytes())
        .await
        .map_err(|e| AppError::hypervisor(format!("write {}: {e}", path.display())))
}

/// Delegate a constrained LXC config append when the broker is enabled.
pub async fn append_lxc_config(name: &str, block: &str) -> ApiResult<()> {
    crate::broker::validate_lxc_name(name).map_err(AppError::validation)?;
    crate::broker::validate_lxc_config_block(block).map_err(AppError::validation)?;
    #[cfg(unix)]
    if let Some(client) = broker_client() {
        return client
            .lxc_config_append(name, block)
            .await
            .map_err(broker_error);
    }
    let path = Path::new("/var/lib/lxc").join(name).join("config");
    let existing = tokio::fs::read_to_string(&path).await.unwrap_or_default();
    tokio::fs::write(&path, format!("{existing}{block}"))
        .await
        .map_err(|e| AppError::hypervisor(format!("write {}: {e}", path.display())))
}

async fn run_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> ApiResult<std::process::Output> {
    tokio::time::timeout(
        timeout,
        command_for(program).kill_on_drop(true).args(args).output(),
    )
    .await
    .map_err(|_| {
        AppError::hypervisor(format!(
            "`{program}` timed out after {} seconds",
            timeout.as_secs()
        ))
    })?
    .map_err(|e| AppError::hypervisor(format!("failed to run `{program}`: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_command_allowlist_rejects_arbitrary_programs() {
        assert!(program_path("zfs").is_some());
        assert!(program_path("virsh").is_some());
        assert!(program_path("sh").is_none());
        assert!(program_path("bash").is_none());
    }

    #[tokio::test]
    async fn commands_are_killed_when_the_timeout_expires() {
        #[cfg(unix)]
        let result = run_with_timeout("sh", &["-c", "sleep 1"], Duration::from_millis(10)).await;
        #[cfg(windows)]
        let result = run_with_timeout(
            "cmd",
            &["/C", "ping 127.0.0.1 -n 3 > NUL"],
            Duration::from_millis(10),
        )
        .await;
        let error = result.expect_err("the command should time out");
        assert!(error.message().contains("timed out"));
    }
}
