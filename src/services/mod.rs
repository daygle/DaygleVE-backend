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
pub mod operations;
pub mod shares;
pub mod store;
pub mod zfs;

use std::net::IpAddr;
use std::sync::Arc;

use crate::config::Config;

/// Aggregate of every subsystem service, owned by [`crate::state::AppState`].
pub struct Services {
    pub auth: auth::AuthService,
    pub kvm: kvm::KvmService,
    pub lxc: lxc::LxcService,
    pub zfs: zfs::ZfsService,
    pub network: network::NetworkService,
    pub operations: Arc<operations::OperationService>,
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
            operations: Arc::new(operations::OperationService::new(config.clone())),
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
///
/// On success it **returns the validated id**, so callers build paths from the
/// sanitizer's output rather than the raw input — making the barrier explicit
/// to both readers and static analysis (breaks path-injection taint).
pub(crate) fn ensure_safe_id(id: &str) -> crate::error::ApiResult<&str> {
    let safe = !id.is_empty()
        && id != "."
        && id != ".."
        // A leading '-' could be parsed as a flag by host CLIs (zfs/virsh/ip).
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if safe {
        Ok(id)
    } else {
        Err(crate::error::AppError::validation(format!(
            "invalid identifier: {id:?}"
        )))
    }
}

/// Validate a ZFS dataset name before it is passed to a host command.
///
/// This deliberately accepts only the subset of ZFS names DaygleVE can safely
/// round-trip through its APIs: `pool/child` components containing ASCII
/// letters, digits, `.`, `-`, `_`, or `:`. Snapshot names containing `@` must
/// use [`ensure_safe_zfs_snapshot`] instead.
pub(crate) fn ensure_safe_zfs_dataset(name: &str) -> crate::error::ApiResult<&str> {
    let safe = !name.is_empty()
        && !name.starts_with('-')
        && !name.starts_with('/')
        && !name.ends_with('/')
        && !name
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'/'));
    if safe {
        Ok(name)
    } else {
        Err(crate::error::AppError::validation(format!(
            "invalid ZFS dataset name: {name:?}"
        )))
    }
}

/// Validate the tag after the `@` in a ZFS snapshot reference.
pub(crate) fn ensure_safe_zfs_snapshot(name: &str) -> crate::error::ApiResult<&str> {
    let safe = !name.is_empty()
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'));
    if safe {
        Ok(name)
    } else {
        Err(crate::error::AppError::validation(format!(
            "invalid ZFS snapshot name: {name:?}"
        )))
    }
}

/// Validate a complete `dataset@snapshot` reference.
#[allow(dead_code)]
pub(crate) fn ensure_safe_zfs_snapshot_ref(name: &str) -> crate::error::ApiResult<&str> {
    let (dataset, snapshot) = name.split_once('@').ok_or_else(|| {
        crate::error::AppError::validation("ZFS snapshot reference must be dataset@snapshot")
    })?;
    if name.matches('@').count() != 1 {
        return Err(crate::error::AppError::validation(
            "ZFS snapshot reference must contain exactly one '@'",
        ));
    }
    ensure_safe_zfs_dataset(dataset)?;
    ensure_safe_zfs_snapshot(snapshot).map(|_| name)
}

/// Validate a canonical PCI BDF such as `0000:01:00.0`.
pub(crate) fn ensure_safe_pci_address(address: &str) -> crate::error::ApiResult<&str> {
    let Some((domain_bus_slot, function)) = address.rsplit_once('.') else {
        return Err(crate::error::AppError::validation("invalid PCI address"));
    };
    let parts: Vec<&str> = domain_bus_slot.split(':').collect();
    let valid = parts.len() == 3
        && parts[0].len() == 4
        && parts[1].len() == 2
        && parts[2].len() == 2
        && function.len() == 1
        && parts
            .iter()
            .all(|part| part.bytes().all(|b| b.is_ascii_hexdigit()))
        && function.bytes().all(|b| b.is_ascii_hexdigit());
    if valid {
        Ok(address)
    } else {
        Err(crate::error::AppError::validation(format!(
            "invalid PCI address: {address:?}"
        )))
    }
}

/// Validate a guest MAC address supplied by an API client.
pub(crate) fn ensure_safe_mac(mac: &str) -> crate::error::ApiResult<&str> {
    let octets: Vec<&str> = mac.split(':').collect();
    let valid = octets.len() == 6
        && octets
            .iter()
            .all(|octet| octet.len() == 2 && octet.bytes().all(|b| b.is_ascii_hexdigit()));
    if valid {
        Ok(mac)
    } else {
        Err(crate::error::AppError::validation(format!(
            "invalid MAC address: {mac:?}"
        )))
    }
}

/// Validate an IPv4/IPv6 CIDR string used in host or guest network config.
pub(crate) fn ensure_safe_cidr<'a>(cidr: &'a str, field: &str) -> crate::error::ApiResult<&'a str> {
    let Some((address, prefix)) = cidr.split_once('/') else {
        return Err(crate::error::AppError::validation(format!(
            "{field} must be an address in CIDR notation"
        )));
    };
    let ip: IpAddr = address.parse().map_err(|_| {
        crate::error::AppError::validation(format!("{field} contains an invalid address"))
    })?;
    let prefix: u8 = prefix.parse().map_err(|_| {
        crate::error::AppError::validation(format!("{field} contains an invalid prefix"))
    })?;
    let max = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return Err(crate::error::AppError::validation(format!(
            "{field} contains an invalid prefix"
        )));
    }
    Ok(cidr)
}

/// Current time as the schema's RFC-3339 string alias.
pub(crate) fn now_ts() -> daygleve_schema::common::Timestamp {
    chrono::Utc::now().to_rfc3339()
}

/// Fresh opaque resource id.
pub(crate) fn new_id() -> daygleve_schema::common::ResourceId {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privileged_input_validators_reject_injection_shapes() {
        assert!(ensure_safe_id("vm-01").is_ok());
        assert!(ensure_safe_id("../etc").is_err());
        assert!(ensure_safe_id("--help").is_err());
        assert!(ensure_safe_zfs_dataset("tank/vm-01").is_ok());
        assert!(ensure_safe_zfs_dataset("tank/../etc").is_err());
        assert!(ensure_safe_zfs_dataset("tank/vm\n01").is_err());
        assert!(ensure_safe_zfs_snapshot("daily_2026-09-04").is_ok());
        assert!(ensure_safe_zfs_snapshot("-r").is_err());
        assert!(ensure_safe_zfs_snapshot_ref("tank/vm@daily").is_ok());
        assert!(ensure_safe_zfs_snapshot_ref("tank/vm@daily@again").is_err());
        assert!(ensure_safe_pci_address("0000:01:00.0").is_ok());
        assert!(ensure_safe_pci_address("../../etc").is_err());
        assert!(ensure_safe_mac("52:54:00:12:34:56").is_ok());
        assert!(ensure_safe_mac("52:54:00:12:34").is_err());
        assert!(ensure_safe_cidr("192.168.1.10/24", "address").is_ok());
        assert!(ensure_safe_cidr("192.168.1.10/33", "address").is_err());
        assert!(ensure_safe_cidr("192.168.1.10/24\n", "address").is_err());
    }
}
