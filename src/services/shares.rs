//! Network storage share (NFS/CIFS) service.
//!
//! Mounts remote filesystems on the node so their ISOs can be offered as VM
//! install media. A share is mounted **read-only** under
//! `<mounts_dir>/<id>`; the KVM service scans those mount points when it
//! enumerates ISO images. CIFS credentials are written to a root-only
//! `credentials=` file and never passed on the command line or returned by the
//! API.
//!
//! Shares are mounted when created and unmounted when deleted. Live mount state
//! is read from `/proc/mounts` at list time, so a share that is not currently
//! mounted (e.g. after a reboot, before a future remount-on-boot hook) reports
//! `disconnected` and contributes no ISOs.

use std::path::PathBuf;
use std::sync::Arc;

use daygleve_schema::share::{CreateShareRequest, NetworkShare, ShareState, ShareType};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::store::JsonStore;
use crate::services::{command, ensure_safe_id, new_id, now_ts};

pub struct ShareService {
    store: JsonStore,
    config: Arc<Config>,
}

impl ShareService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            store: JsonStore::new(&config.state_dir, "shares"),
            config,
        }
    }

    /// All configured shares, each with live mount state overlaid.
    pub async fn list(&self) -> ApiResult<Vec<NetworkShare>> {
        let mounted = read_mounts().await;
        let mut shares: Vec<NetworkShare> = self.store.list().await?;
        for share in &mut shares {
            // Preserve an `error` recorded at create time; otherwise reflect
            // whether the mount point is currently mounted.
            if share.state != ShareState::Error {
                share.state = if mounted.iter().any(|m| m == &share.mount_point) {
                    ShareState::Connected
                } else {
                    ShareState::Disconnected
                };
            }
        }
        shares.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(shares)
    }

    /// Mount points (with their share name) of every currently-connected share.
    /// Used by the KVM service to discover ISOs living on shares.
    pub async fn iso_roots(&self) -> Vec<(String, PathBuf)> {
        let mounted = read_mounts().await;
        let shares: Vec<NetworkShare> = self.store.list().await.unwrap_or_default();
        shares
            .into_iter()
            .filter(|s| mounted.iter().any(|m| m == &s.mount_point))
            .map(|s| (s.name, PathBuf::from(s.mount_point)))
            .collect()
    }

    /// Add and mount a network share.
    pub async fn create(&self, req: CreateShareRequest) -> ApiResult<NetworkShare> {
        // The name is user-facing and must be safe to build a path/id from.
        ensure_safe_id(&req.name)?;
        // `local` is reserved: it labels the node's built-in ISO library in
        // IsoImage.storage, so a share may not claim that name.
        if req.name.eq_ignore_ascii_case("local") {
            return Err(AppError::validation("'local' is a reserved share name"));
        }
        validate_host(&req.server, "server")?;
        validate_export(&req.export_path)?;
        if let Some(opts) = &req.options {
            validate_options(opts)?;
        }

        let id = new_id();
        let mount_point = self.config.mounts_dir.join(&id);
        let mount_point_str = mount_point.to_string_lossy().into_owned();

        tokio::fs::create_dir_all(&mount_point)
            .await
            .map_err(|e| AppError::internal(format!("cannot create mount point: {e}")))?;

        // Assemble the mount command (argv, never a shell) and, for CIFS, a
        // root-only credentials file.
        let cred_path = self.cred_path(&id);
        let mount_result = match req.share_type {
            ShareType::Nfs => {
                let source = format!("{}:{}", req.server, req.export_path);
                let opts = merge_options("ro", req.options.as_deref());
                command::run_ok(
                    "mount",
                    &["-t", "nfs", "-o", &opts, &source, &mount_point_str],
                )
                .await
            }
            ShareType::Cifs => {
                write_cifs_credentials(
                    &cred_path,
                    req.username.as_deref(),
                    req.password.as_deref(),
                    req.domain.as_deref(),
                )
                .await?;
                let source = format!("//{}/{}", req.server, req.export_path);
                let base = format!(
                    "ro,credentials={},file_mode=0444,dir_mode=0555",
                    cred_path.to_string_lossy()
                );
                let opts = merge_options(&base, req.options.as_deref());
                command::run_ok(
                    "mount",
                    &["-t", "cifs", "-o", &opts, &source, &mount_point_str],
                )
                .await
            }
        };

        if let Err(e) = mount_result {
            // Clean up so a failed attempt leaves nothing behind.
            let _ = tokio::fs::remove_file(&cred_path).await;
            let _ = tokio::fs::remove_dir(&mount_point).await;
            return Err(AppError::hypervisor(format!(
                "failed to mount share: {}",
                e.message()
            )));
        }

        let share = NetworkShare {
            id: id.clone(),
            name: req.name,
            share_type: req.share_type,
            server: req.server,
            export_path: req.export_path,
            mount_point: mount_point_str,
            state: ShareState::Connected,
            read_only: true,
            username: req.username,
            options: req.options,
            last_error: None,
            created_at: now_ts(),
        };
        self.store.put(&id, &share).await?;
        Ok(share)
    }

    /// Unmount and forget a share.
    pub async fn delete(&self, id: &str) -> ApiResult<()> {
        let share: NetworkShare = self
            .store
            .get(id)
            .await?
            .ok_or_else(|| AppError::not_found("share not found"))?;

        // If the share is currently mounted, unmount it and require success:
        // never remove the record while a live mount would be left orphaned on
        // the host (and invisible to the API). A share that isn't mounted (e.g.
        // after a reboot) skips straight to cleanup.
        let mounted = read_mounts().await;
        if mounted.iter().any(|m| m == &share.mount_point) {
            command::run_ok("umount", &[&share.mount_point])
                .await
                .map_err(|e| {
                    AppError::conflict(format!(
                        "could not unmount the share (is it in use?): {}",
                        e.message()
                    ))
                })?;
        }

        let _ = tokio::fs::remove_file(self.cred_path(id)).await;
        let _ = tokio::fs::remove_dir(&share.mount_point).await;
        self.store.delete(id).await?;
        Ok(())
    }

    fn cred_path(&self, id: &str) -> PathBuf {
        self.config.mounts_dir.join(format!("{id}.cred"))
    }
}

/// Read the set of mount-point targets currently mounted, from `/proc/mounts`.
async fn read_mounts() -> Vec<String> {
    let content = match tokio::fs::read_to_string("/proc/mounts").await {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    content
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        // /proc/mounts octal-escapes spaces etc.; our mount points live under
        // the (space-free) mounts_dir, so a direct compare is sufficient.
        .map(|target| target.to_string())
        .collect()
}

/// Write a CIFS credentials file readable only by root (mode 0600).
async fn write_cifs_credentials(
    path: &std::path::Path,
    username: Option<&str>,
    password: Option<&str>,
    domain: Option<&str>,
) -> ApiResult<()> {
    for (field, value) in [
        ("username", username.unwrap_or("")),
        ("password", password.unwrap_or("")),
        ("domain", domain.unwrap_or("")),
    ] {
        if value
            .chars()
            .any(|c| c.is_control() || c == '\n' || c == '\r')
        {
            return Err(AppError::validation(format!(
                "{field} contains invalid characters"
            )));
        }
    }

    let mut body = String::new();
    body.push_str(&format!("username={}\n", username.unwrap_or("guest")));
    body.push_str(&format!("password={}\n", password.unwrap_or("")));
    if let Some(domain) = domain {
        body.push_str(&format!("domain={domain}\n"));
    }

    tokio::fs::write(path, body)
        .await
        .map_err(|e| AppError::internal(format!("cannot write credentials: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|e| AppError::internal(format!("cannot secure credentials: {e}")))?;
    }
    Ok(())
}

/// Combine a required base option string with optional user-supplied options.
fn merge_options(base: &str, extra: Option<&str>) -> String {
    match extra.map(str::trim).filter(|s| !s.is_empty()) {
        Some(extra) => format!("{base},{extra}"),
        None => base.to_string(),
    }
}

/// A hostname or IP: non-empty, no whitespace, not flag-like, and restricted to
/// characters valid in a host or address.
fn validate_host(value: &str, field: &str) -> ApiResult<()> {
    if value.is_empty() || value.starts_with('-') || value.len() > 253 {
        return Err(AppError::validation(format!("{field} is invalid")));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'))
    {
        return Err(AppError::validation(format!(
            "{field} contains invalid characters"
        )));
    }
    Ok(())
}

/// An NFS export path or CIFS share name: non-empty, not flag-like, and free of
/// whitespace, control characters, and comma (which would split mount options).
fn validate_export(value: &str) -> ApiResult<()> {
    if value.is_empty() || value.starts_with('-') || value.len() > 1024 {
        return Err(AppError::validation("export is invalid"));
    }
    if value
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == ',')
    {
        return Err(AppError::validation("export contains invalid characters"));
    }
    Ok(())
}

/// Mount option keys the caller may not set: anything that would carry
/// credentials (handled separately via a root-only file) or override the
/// enforced read-only mount.
const DENIED_OPTION_KEYS: &[&str] = &[
    "credentials",
    "cred",
    "password",
    "pass",
    "pass2",
    "password2",
    "username",
    "user",
    "user2",
    "domain",
    "dom",
    "workgroup",
    "sec",
    "guest",
    "rw", // would override the enforced read-only mount
];

/// User-supplied extra mount options: restricted to option-like characters, and
/// checked key-by-key so no option can smuggle in credentials or flip the mount
/// to read-write. Credentials are supplied via the dedicated fields and written
/// to a root-only file; the mount is always read-only.
fn validate_options(value: &str) -> ApiResult<()> {
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '=' | ',' | '.' | '_' | '-' | ':'))
    {
        return Err(AppError::validation("options contain invalid characters"));
    }
    for opt in value.split(',') {
        let opt = opt.trim();
        if opt.is_empty() {
            continue;
        }
        // The key is everything before the first '=' (or the whole token for a
        // bare flag like `rw`).
        let key = opt
            .split('=')
            .next()
            .unwrap_or(opt)
            .trim()
            .to_ascii_lowercase();
        if DENIED_OPTION_KEYS.contains(&key.as_str()) {
            return Err(AppError::validation(format!(
                "mount option '{key}' is not allowed; credentials use the dedicated fields and the mount is always read-only"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_options_appends_extras() {
        assert_eq!(merge_options("ro", None), "ro");
        assert_eq!(merge_options("ro", Some("")), "ro");
        assert_eq!(merge_options("ro", Some("vers=4.1")), "ro,vers=4.1");
    }

    #[test]
    fn rejects_flag_like_and_bad_chars() {
        assert!(validate_host("-x", "server").is_err());
        assert!(validate_host("nas.local", "server").is_ok());
        assert!(validate_host("a b", "server").is_err());
        assert!(validate_export("/export/isos").is_ok());
        assert!(validate_export("-rf").is_err());
        assert!(validate_export("a,b").is_err());
    }

    #[test]
    fn options_block_credential_smuggling() {
        // Benign tuning options are allowed.
        assert!(validate_options("vers=3.0").is_ok());
        assert!(validate_options("vers=4.1,nconnect=4").is_ok());
        // Credentials must not travel through mount options.
        assert!(validate_options("credentials=/etc/shadow").is_err());
        assert!(validate_options("password=secret").is_err());
        assert!(validate_options("pass=secret").is_err());
        assert!(validate_options("username=admin").is_err());
        assert!(validate_options("user=admin").is_err());
        assert!(validate_options("domain=corp").is_err());
        // rw must not override the enforced read-only mount.
        assert!(validate_options("rw").is_err());
        assert!(validate_options("vers=3.0,rw").is_err());
        // Bad characters are rejected.
        assert!(validate_options("bad opt").is_err());
    }
}
