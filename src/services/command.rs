//! Thin async wrapper around spawning host commands.
//!
//! The service layer drives the host by shelling out to `virsh`, `qemu-img`,
//! `zfs`/`zpool`, `ip`/`bridge`, `lxc-*` and friends (the same approach
//! Proxmox takes). Centralising the spawn here gives every call uniform error
//! mapping into [`AppError`] and one place to reason about failures.

use std::time::Duration;

use tokio::process::Command;

/// Upper bound for a host command invoked by an HTTP request. Long-running
/// workflows should move to the job system instead of extending this limit.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

use crate::error::{ApiResult, AppError};

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

/// Return a validation error when a call site attempts to invoke an
/// unapproved host program.
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

/// Build a host-tool command with a fixed executable path and a minimal
/// environment. This prevents PATH lookup and loader-related environment
/// variables from becoming an execution-control surface.
pub(crate) fn new(program: &str) -> ApiResult<Command> {
    let executable = validate_program(program)?;
    Ok(command_for(executable))
}

/// Run `program args...`, returning captured stdout on success.
///
/// A non-zero exit maps to a `HypervisorError` carrying the trimmed stderr; a
/// spawn failure (including the binary not being installed) maps the same way.
pub async fn run(program: &str, args: &[&str]) -> ApiResult<String> {
    let executable = validate_program(program)?;
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

/// Run a command purely for its side effect, discarding stdout.
pub async fn run_ok(program: &str, args: &[&str]) -> ApiResult<()> {
    run(program, args).await.map(|_| ())
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

/// Like [`run`], but returns `Ok(None)` when the binary is not installed.
///
/// List/inventory endpoints use this so a development host without `zfs`/`virsh`
/// degrades to "nothing to show" instead of a 502. A tool that *is* present but
/// exits non-zero still surfaces as an error.
pub async fn run_optional(program: &str, args: &[&str]) -> ApiResult<Option<String>> {
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
