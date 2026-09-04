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

/// Run `program args...`, returning captured stdout on success.
///
/// A non-zero exit maps to a `HypervisorError` carrying the trimmed stderr; a
/// spawn failure (including the binary not being installed) maps the same way.
pub async fn run(program: &str, args: &[&str]) -> ApiResult<String> {
    let output = run_with_timeout(program, args, COMMAND_TIMEOUT).await?;

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
        Command::new(program).kill_on_drop(true).args(args).output(),
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
    match tokio::time::timeout(
        COMMAND_TIMEOUT,
        Command::new(program).kill_on_drop(true).args(args).output(),
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
