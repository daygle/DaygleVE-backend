//! ZFS storage service: pools, datasets, snapshots and clones.
//!
//! Drives the `zpool`/`zfs` CLIs and parses their `-Hp` (script-friendly,
//! parseable) output. ZFS itself is the source of truth — nothing is cached.
//! On a host without ZFS installed, the list endpoints degrade to empty rather
//! than erroring (see [`command::run_optional`]).

use std::sync::Arc;

use daygleve_schema::storage::{
    CloneSnapshotRequest, CreateDatasetRequest, CreateSnapshotRequest, Dataset, DatasetKind, Pool,
    PoolHealth, Snapshot,
};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::command;

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
        if req.name.trim().is_empty() {
            return Err(AppError::validation("dataset name must not be empty"));
        }
        if matches!(req.kind, DatasetKind::Volume) && req.size_gib.is_none() {
            return Err(AppError::validation("size_gib is required for volumes"));
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
        let out = match command::run_optional(
            "zfs",
            &[
                "list",
                "-t",
                "snapshot",
                "-Hp",
                "-o",
                "name,used,creation",
                "-r",
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
        if req.name.trim().is_empty() {
            return Err(AppError::validation("snapshot name must not be empty"));
        }
        let full = format!("{dataset_id}@{}", req.name);

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
        if req.target.trim().is_empty() {
            return Err(AppError::validation("target must not be empty"));
        }
        command::run_ok("zfs", &["clone", snapshot_id, &req.target]).await?;
        self.get_dataset(&req.target).await
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

fn to_argv(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
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
