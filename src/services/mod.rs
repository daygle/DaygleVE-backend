//! The service layer: one module per hypervisor/host subsystem.
//!
//! Handlers in [`crate::api`] stay thin — they parse/authorize requests and
//! delegate all host interaction to these services. Each service is where real
//! `libvirt`/`qemu`, `lxc`, `zfs`, `ip`/`bridge`, `vfio` and `/proc` calls will
//! live. In this architecture-setup scaffold they are backed by in-memory
//! state and clearly marked `TODO` stubs so the API shape and boundaries are
//! exercisable end-to-end.

pub mod auth;
pub mod gpu;
pub mod kvm;
pub mod lxc;
pub mod metrics;
pub mod network;
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
}

impl Services {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            auth: auth::AuthService::new(),
            kvm: kvm::KvmService::new(),
            lxc: lxc::LxcService::new(),
            zfs: zfs::ZfsService::new(config.clone()),
            network: network::NetworkService::new(),
            gpu: gpu::GpuService::new(),
            metrics: metrics::MetricsService::new(),
        }
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
