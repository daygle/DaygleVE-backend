//! ZFS storage service: pools, datasets, snapshots and clones.
//!
//! Drives the `zpool`/`zfs` CLIs and parses their `-Hp` (script-friendly,
//! parseable) output. ZFS itself is the source of truth - nothing is cached.
//! On a host without ZFS installed, the list endpoints degrade to empty rather
//! than erroring (see [`command::run_optional`]).

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use daygleve_schema::storage::{
    CloneSnapshotRequest, CreateDatasetRequest, CreatePoolRequest, CreateSnapshotRequest, Dataset,
    DatasetKind, Pool, PoolHealth, PoolLayout, RawDisk, SmartReport, Snapshot, WipeDiskRequest,
};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::{
    command, ensure_safe_zfs_dataset, ensure_safe_zfs_snapshot, ensure_safe_zfs_snapshot_ref,
};

/// Columns requested from `zfs list` for a [`Dataset`].
const DATASET_COLS: &str = "name,used,avail,mountpoint,compression,type,creation";

pub struct ZfsService {
    #[allow(dead_code)]
    config: Arc<Config>,
}

impl ZfsService {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    pub async fn list_pools(&self) -> ApiResult<Vec<Pool>> {
        let out = match command::run_optional(
            "zpool",
            &["list", "-Hp", "-o", "name,size,alloc,free,frag,health"],
        )
        .await?
        {
            Some(out) => out,
            None => return Ok(Vec::new()),
        };

        let mut pools = Vec::new();
        for line in out.lines().filter(|l| !l.trim().is_empty()) {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 6 {
                continue;
            }
            pools.push(Pool {
                name: f[0].to_string(),
                size_bytes: parse_u64(f[1]),
                allocated_bytes: parse_u64(f[2]),
                free_bytes: parse_u64(f[3]),
                fragmentation_pct: parse_pct(f[4]),
                health: parse_health(f[5]),
            });
        }
        Ok(pools)
    }

    /// Enumerate physical block devices from sysfs. Virtual devices and
    /// partitions are excluded; holder links and mounted filesystems mark a
    /// disk as in use so destructive operations fail closed.
    pub async fn list_raw_disks(&self) -> ApiResult<Vec<RawDisk>> {
        let mut out = Vec::new();
        let mut rd = match tokio::fs::read_dir("/sys/block").await {
            Ok(rd) => rd,
            Err(_) => return Ok(out),
        };
        let zpool_devices = self.zpool_device_paths().await?;
        while let Some(entry) = rd
            .next_entry()
            .await
            .map_err(|e| AppError::internal(format!("read /sys/block: {e}")))?
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            let sys = entry.path();
            if !is_physical_disk_name(&name)
                || tokio::fs::metadata(sys.join("partition")).await.is_ok()
            {
                continue;
            }
            let size_bytes = tokio::fs::read_to_string(sys.join("size"))
                .await
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0)
                .saturating_mul(512);
            let model = read_trimmed_file(&sys.join("device/model"))
                .await
                .unwrap_or_default();
            let serial = read_trimmed_file(&sys.join("device/serial")).await;
            let rotational = read_trimmed_file(&sys.join("queue/rotational"))
                .await
                .is_some_and(|v| v == "1");
            let path = format!("/dev/{name}");
            let holders = tokio::fs::read_dir(sys.join("holders"))
                .await
                .ok()
                .map(|mut d| async move { d.next_entry().await.ok().flatten().is_some() });
            let has_holder = match holders {
                Some(f) => f.await,
                None => false,
            };
            let mounted = mounted_device_names().await.iter().any(|mounted| {
                mounted == &name
                    || mounted
                        .strip_prefix(&name)
                        .is_some_and(|suffix| suffix.chars().all(|c| c.is_ascii_digit()))
            });
            out.push(RawDisk {
                path: path.clone(),
                model,
                serial,
                size_bytes,
                rotational,
                in_use: has_holder || mounted || zpool_devices.contains(&path),
            });
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    pub async fn smart_report(&self, path: &str) -> ApiResult<SmartReport> {
        let disk = self.raw_disk(path).await?;
        let checked_at = crate::services::now_ts();
        let output = match command::run_optional("smartctl", &["-j", "-a", &disk.path]).await? {
            Some(output) => output,
            None => {
                return Ok(SmartReport {
                    path: disk.path,
                    supported: false,
                    passed: None,
                    health: None,
                    temperature_c: None,
                    power_on_hours: None,
                    checked_at,
                })
            }
        };
        let value: serde_json::Value = serde_json::from_str(&output)
            .map_err(|e| AppError::hypervisor(format!("parse smartctl JSON: {e}")))?;
        let supported = value
            .pointer("smart_support.available")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(true);
        let passed = value
            .pointer("smart_status.passed")
            .and_then(serde_json::Value::as_bool);
        let health = passed.map(|ok| {
            if ok {
                "PASSED".to_string()
            } else {
                "FAILED".to_string()
            }
        });
        let temperature_c = value
            .pointer("temperature.current")
            .and_then(serde_json::Value::as_i64)
            .map(|v| v as i32);
        let power_on_hours = value
            .pointer("power_on_time.hours")
            .and_then(serde_json::Value::as_u64);
        Ok(SmartReport {
            path: disk.path,
            supported,
            passed,
            health,
            temperature_c,
            power_on_hours,
            checked_at,
        })
    }

    pub async fn wipe_disk(&self, req: WipeDiskRequest) -> ApiResult<()> {
        let disk = self.raw_disk(&req.path).await?;
        if req.confirm != disk.path {
            return Err(AppError::validation(
                "confirm must exactly match the disk path",
            ));
        }
        if disk.in_use {
            return Err(AppError::conflict("refusing to wipe a disk that is in use"));
        }
        command::run_ok("wipefs", &["-a", &disk.path]).await
    }

    pub async fn create_pool(&self, req: CreatePoolRequest) -> ApiResult<Pool> {
        ensure_pool_name(&req.name)?;
        let required = min_devices(req.layout);
        if req.devices.len() < required {
            return Err(AppError::validation(format!(
                "{:?} requires at least {required} devices",
                req.layout
            )));
        }
        let mut unique = HashSet::new();
        let disks = self.list_raw_disks().await?;
        let mut paths = Vec::with_capacity(req.devices.len());
        for path in &req.devices {
            let disk = disks
                .iter()
                .find(|d| d.path == *path)
                .ok_or_else(|| AppError::not_found(format!("raw disk {path} not found")))?;
            if !unique.insert(path) {
                return Err(AppError::validation("pool devices must be unique"));
            }
            if disk.in_use {
                return Err(AppError::conflict(format!("disk {path} is in use")));
            }
            paths.push(disk.path.clone());
        }
        let layout = match req.layout {
            PoolLayout::Stripe => None,
            PoolLayout::Mirror => Some("mirror"),
            PoolLayout::Raidz1 => Some("raidz1"),
            PoolLayout::Raidz2 => Some("raidz2"),
            PoolLayout::Raidz3 => Some("raidz3"),
        };
        let mut args = vec!["create".to_string()];
        if req.force {
            args.push("-f".to_string());
        }
        args.push(req.name.clone());
        if let Some(layout) = layout {
            args.push(layout.to_string());
        }
        args.extend(paths);
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        command::run_ok("zpool", &argv).await?;
        self.list_pools()
            .await?
            .into_iter()
            .find(|p| p.name == req.name)
            .ok_or_else(|| AppError::hypervisor("pool was created but could not be read back"))
    }

    pub async fn list_datasets(&self) -> ApiResult<Vec<Dataset>> {
        let out = match command::run_optional("zfs", &["list", "-Hp", "-o", DATASET_COLS]).await? {
            Some(out) => out,
            None => return Ok(Vec::new()),
        };
        Ok(out
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(parse_dataset_line)
            .collect())
    }

    pub async fn create_dataset(&self, req: CreateDatasetRequest) -> ApiResult<Dataset> {
        ensure_safe_zfs_dataset(&req.name)?;
        ensure_safe_zfs_dataset(&self.config.default_pool)?;
        if matches!(req.kind, DatasetKind::Volume) && req.size_gib.is_none_or(|size| size == 0) {
            return Err(AppError::validation("size_gib must be >= 1 for volumes"));
        }
        if let Some(compression) = req.compression.as_deref() {
            if !is_safe_compression(compression) {
                return Err(AppError::validation("invalid compression property"));
            }
        }
        if matches!(req.kind, DatasetKind::Filesystem) && req.size_gib.is_some() {
            return Err(AppError::validation(
                "size_gib is only valid for volume datasets",
            ));
        }

        let mut args: Vec<String> = vec!["create".into()];
        if let Some(comp) = &req.compression {
            args.push("-o".into());
            args.push(format!("compression={comp}"));
        }
        if matches!(req.kind, DatasetKind::Volume) {
            let size = req.size_gib.expect("checked above");
            args.push("-V".into());
            args.push(format!("{size}G"));
        }
        args.push(req.name.clone());

        let argv = to_argv(&args);
        command::run_ok("zfs", &argv).await?;
        self.get_dataset(&req.name).await
    }

    pub async fn list_snapshots(&self, dataset_id: &str) -> ApiResult<Vec<Snapshot>> {
        ensure_safe_zfs_dataset(dataset_id)?;
        // No `-r`: we only want this dataset's own snapshots, so recursing into
        // descendants and filtering them back out is wasted work on large trees.
        let out = match command::run_optional(
            "zfs",
            &[
                "list",
                "-t",
                "snapshot",
                "-Hp",
                "-o",
                "name,used,creation",
                dataset_id,
            ],
        )
        .await?
        {
            Some(out) => out,
            None => return Ok(Vec::new()),
        };

        let prefix = format!("{dataset_id}@");
        Ok(out
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter(|l| l.starts_with(&prefix))
            .filter_map(parse_snapshot_line)
            .collect())
    }

    pub async fn create_snapshot(
        &self,
        dataset_id: &str,
        req: CreateSnapshotRequest,
    ) -> ApiResult<Snapshot> {
        ensure_safe_zfs_dataset(dataset_id)?;
        let snapshot = ensure_safe_zfs_snapshot(req.name.trim())?;
        let full = format!("{dataset_id}@{snapshot}");

        let mut args: Vec<String> = vec!["snapshot".into()];
        if req.recursive {
            args.push("-r".into());
        }
        args.push(full.clone());
        let argv = to_argv(&args);
        command::run_ok("zfs", &argv).await?;

        let out = command::run(
            "zfs",
            &[
                "list",
                "-t",
                "snapshot",
                "-Hp",
                "-o",
                "name,used,creation",
                &full,
            ],
        )
        .await?;
        out.lines()
            .next()
            .and_then(parse_snapshot_line)
            .ok_or_else(|| AppError::hypervisor(format!("snapshot {full} not found after create")))
    }

    pub async fn clone_snapshot(
        &self,
        snapshot_id: &str,
        req: CloneSnapshotRequest,
    ) -> ApiResult<Dataset> {
        ensure_safe_zfs_snapshot_ref(snapshot_id)?;
        ensure_safe_zfs_dataset(&req.target)?;
        command::run_ok("zfs", &["clone", snapshot_id, &req.target]).await?;
        self.get_dataset(&req.target).await
    }

    async fn raw_disk(&self, path: &str) -> ApiResult<RawDisk> {
        self.list_raw_disks()
            .await?
            .into_iter()
            .find(|disk| disk.path == path)
            .ok_or_else(|| AppError::not_found(format!("raw disk {path} not found")))
    }

    async fn zpool_device_paths(&self) -> ApiResult<HashSet<String>> {
        let mut paths = HashSet::new();
        let output = match command::run_optional("zpool", &["status", "-P", "-L"]).await? {
            Some(v) => v,
            None => return Ok(paths),
        };
        for token in output.split_whitespace() {
            if token.starts_with("/dev/") {
                paths.insert(token.to_string());
            }
        }
        Ok(paths)
    }

    /// Read a single dataset back by name.
    async fn get_dataset(&self, name: &str) -> ApiResult<Dataset> {
        let out = command::run("zfs", &["list", "-Hp", "-o", DATASET_COLS, name]).await?;
        out.lines()
            .next()
            .and_then(parse_dataset_line)
            .ok_or_else(|| AppError::hypervisor(format!("dataset {name} not found after create")))
    }
}
fn is_physical_disk_name(name: &str) -> bool {
    !(name.starts_with("loop")
        || name.starts_with("ram")
        || name.starts_with("zram")
        || name.starts_with("dm-")
        || name.starts_with("md")
        || name.starts_with("sr"))
}

async fn read_trimmed_file(path: &Path) -> Option<String> {
    tokio::fs::read_to_string(path)
        .await
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

async fn mounted_device_names() -> HashSet<String> {
    let mut names = HashSet::new();
    if let Ok(text) = tokio::fs::read_to_string("/proc/mounts").await {
        for line in text.lines() {
            if let Some(device) = line.split_whitespace().next() {
                if let Some(name) = device.strip_prefix("/dev/") {
                    names.insert(name.split('/').next().unwrap_or(name).to_string());
                }
            }
        }
    }
    names
}

fn ensure_pool_name(name: &str) -> ApiResult<()> {
    if name.is_empty()
        || name.len() > 64
        || name.starts_with('-')
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(AppError::validation(
            "pool name must be a safe single component",
        ));
    }
    Ok(())
}

fn min_devices(layout: PoolLayout) -> usize {
    match layout {
        PoolLayout::Stripe => 1,
        PoolLayout::Mirror => 2,
        PoolLayout::Raidz1 => 3,
        PoolLayout::Raidz2 => 4,
        PoolLayout::Raidz3 => 5,
    }
}

fn to_argv(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

fn is_safe_compression(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    let numbered = |prefix: &str, max: u8| {
        value
            .strip_prefix(prefix)
            .and_then(|level| level.parse::<u8>().ok())
            .is_some_and(|level| (1..=max).contains(&level))
    };
    matches!(
        value.as_str(),
        "on" | "off" | "lz4" | "gzip" | "zle" | "zstd" | "zstd-fast"
    ) || numbered("gzip-", 9)
        || numbered("zstd-", 16)
}

fn parse_u64(s: &str) -> u64 {
    s.trim().parse().unwrap_or(0)
}

/// Parse a fragmentation column that may be `"-"`, `"12"` or `"12%"`.
fn parse_pct(s: &str) -> u8 {
    s.trim().trim_end_matches('%').parse().unwrap_or(0)
}

fn parse_health(s: &str) -> PoolHealth {
    match s.trim().to_ascii_uppercase().as_str() {
        "ONLINE" => PoolHealth::Online,
        "DEGRADED" => PoolHealth::Degraded,
        "FAULTED" => PoolHealth::Faulted,
        "OFFLINE" => PoolHealth::Offline,
        _ => PoolHealth::Unavail,
    }
}

/// Convert a unix-seconds string into an RFC-3339 timestamp.
fn unix_to_rfc3339(secs: &str) -> String {
    secs.trim()
        .parse::<i64>()
        .ok()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default()
}

/// Parse one `zfs list` row using [`DATASET_COLS`].
fn parse_dataset_line(line: &str) -> Option<Dataset> {
    let f: Vec<&str> = line.split('\t').collect();
    if f.len() < 7 {
        return None;
    }
    let kind = match f[5].trim() {
        "volume" => DatasetKind::Volume,
        _ => DatasetKind::Filesystem,
    };
    let mountpoint = match f[3].trim() {
        "" | "-" | "none" | "legacy" => None,
        m => Some(m.to_string()),
    };
    Some(Dataset {
        id: f[0].to_string(),
        name: f[0].to_string(),
        kind,
        used_bytes: parse_u64(f[1]),
        available_bytes: parse_u64(f[2]),
        mountpoint,
        compression: f[4].trim().to_string(),
        created_at: unix_to_rfc3339(f[6]),
    })
}

/// Parse one `zfs list -t snapshot` row of `name,used,creation`.
fn parse_snapshot_line(line: &str) -> Option<Snapshot> {
    let f: Vec<&str> = line.split('\t').collect();
    if f.len() < 3 {
        return None;
    }
    let name = f[0].to_string();
    let dataset = name.split('@').next().unwrap_or(&name).to_string();
    Some(Snapshot {
        id: name.clone(),
        name,
        dataset,
        used_bytes: parse_u64(f[1]),
        created_at: unix_to_rfc3339(f[2]),
    })
}
