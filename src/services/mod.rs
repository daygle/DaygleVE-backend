//! The service layer: one module per hypervisor/host subsystem.
//!
//! Handlers in [`crate::api`] stay thin — they parse/authorize requests and
//! delegate all host interaction to these services. Each service drives the
//! host by shelling out to the real tools (`virsh`/`qemu-img`, `lxc-*`,
//! `zfs`/`zpool`, `ip`/`bridge`, `vfio` via sysfs, `/proc`), with DaygleVE's
//! own structured records persisted via [`store::JsonStore`]. See
//! [`command`] for the spawn wrapper.

pub mod auth;
pub mod command;
pub mod gpu;
pub mod kvm;
pub mod lxc;
pub mod metrics;
pub mod network;
pub mod shares;
pub mod store;
pub mod zfs;

use std::sync::Arc;

use crate::config::Config;

/// Aggregate of every subsystem service, owned by [`crate::state::AppState`].
pub struct Services {
    pub auth: auth::AuthService,
    pub kvm: kvm::KvmService,
    pub lxc: lxc::LxcService,
    pub zfs: zfs::ZfsService,
    pub network: network::NetworkService,
    pub gpu: gpu::GpuService,
    pub metrics: metrics::MetricsService,
    /// Network storage shares (NFS/CIFS). Shared with the KVM service so it can
    /// enumerate ISOs living on mounted shares.
    pub shares: Arc<shares::ShareService>,
}

impl Services {
    pub fn new(config: Arc<Config>) -> Self {
        let shares = Arc::new(shares::ShareService::new(config.clone()));
        Self {
            auth: auth::AuthService::new(config.clone()),
            kvm: kvm::KvmService::new(config.clone(), shares.clone()),
            lxc: lxc::LxcService::new(config.clone()),
            zfs: zfs::ZfsService::new(config.clone()),
            network: network::NetworkService::new(config.clone()),
            gpu: gpu::GpuService::new(),
            metrics: metrics::MetricsService::new(),
            shares,
        }
    }
}

/// Reject any id/name that could escape or traverse a filesystem path before
/// it is used to build one. Allows ASCII alphanumerics plus `.`, `-`, `_`;
/// forbids the empty string, `.` and `..`. This is the sanitizer guarding every
/// user-influenced path in the service layer (VM/container tmp files, the JSON
/// record store, LXC config paths).
pub(crate) fn ensure_safe_id(id: &str) -> crate::error::ApiResult<()> {
    let safe = !id.is_empty()
        && id != "."
        && id != ".."
        // A leading '-' could be parsed as a flag by host CLIs (zfs/virsh/ip).
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if safe {
        Ok(())
    } else {
        Err(crate::error::AppError::validation(format!(
            "invalid identifier: {id:?}"
        )))
    }
}

/// Current time as the schema's RFC-3339 string alias.
pub(crate) fn now_ts() -> daygleve_schema::common::Timestamp {
    chrono::Utc::now().to_rfc3339()
}

/// Fresh opaque resource id.
pub(crate) fn new_id() -> daygleve_schema::common::ResourceId {
    uuid::Uuid::new_v4().to_string()
}
