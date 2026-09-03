//! Thin async wrapper around spawning host commands.
//!
//! The service layer drives the host by shelling out to `virsh`, `qemu-img`,
//! `zfs`/`zpool`, `ip`/`bridge`, `lxc-*` and friends (the same approach
//! Proxmox takes). Centralising the spawn here gives every call uniform error
//! mapping into [`AppError`] and one place to reason about failures.

use tokio::process::Command;

use crate::error::{ApiResult, AppError};

/// Run `program args...`, returning captured stdout on success.
///
/// A non-zero exit maps to a `HypervisorError` carrying the trimmed stderr; a
/// spawn failure (including the binary not being installed) maps the same way.
pub async fn run(program: &str, args: &[&str]) -> ApiResult<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| AppError::hypervisor(format!("failed to run `{program}`: {e}")))?;

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

/// Like [`run`], but returns `Ok(None)` when the binary is not installed.
///
/// List/inventory endpoints use this so a development host without `zfs`/`virsh`
/// degrades to "nothing to show" instead of a 502. A tool that *is* present but
/// exits non-zero still surfaces as an error.
pub async fn run_optional(program: &str, args: &[&str]) -> ApiResult<Option<String>> {
    match Command::new(program).args(args).output().await {
        Ok(output) if output.status.success() => {
            Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(AppError::hypervisor(format!(
                "`{program} {}` failed: {}",
                args.join(" "),
                stderr.trim()
            )))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(AppError::hypervisor(format!(
            "failed to run `{program}`: {e}"
        ))),
    }
}
