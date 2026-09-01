//! ZFS storage service: pools, datasets, snapshots and clones.
//!
//! TODO(zfs): shell out to `zpool`/`zfs` (or bind libzfs) and parse output.
//! The scaffold returns representative data derived from config.

use std::sync::Arc;

use daygleve_schema::storage::{
    CloneSnapshotRequest, CreateDatasetRequest, CreateSnapshotRequest, Dataset, DatasetKind, Pool,
    PoolHealth, Snapshot,
};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::{new_id, now_ts};

pub struct ZfsService {
    config: Arc<Config>,
}

impl ZfsService {
    pub fn new(config: Arc<Config>) -> Self {
        Self { config }
    }

    pub fn list_pools(&self) -> Vec<Pool> {
        // TODO(zfs): parse `zpool list -Hp`.
        vec![Pool {
            name: self.config.default_pool.clone(),
            health: PoolHealth::Online,
            size_bytes: 0,
            allocated_bytes: 0,
            free_bytes: 0,
            fragmentation_pct: 0,
        }]
    }

    pub fn list_datasets(&self) -> Vec<Dataset> {
        // TODO(zfs): parse `zfs list -Hp -o name,used,available,...`.
        Vec::new()
    }

    pub fn create_dataset(&self, req: CreateDatasetRequest) -> ApiResult<Dataset> {
        if matches!(req.kind, DatasetKind::Volume) && req.size_gib.is_none() {
            return Err(AppError::validation("size_gib is required for volumes"));
        }
        // TODO(zfs): `zfs create` (add `-V <size>` for volumes).
        Ok(Dataset {
            id: new_id(),
            name: req.name,
            kind: req.kind,
            used_bytes: 0,
            available_bytes: 0,
            mountpoint: None,
            compression: req.compression.unwrap_or_else(|| "lz4".to_string()),
            created_at: now_ts(),
        })
    }

    pub fn list_snapshots(&self, _dataset_id: &str) -> ApiResult<Vec<Snapshot>> {
        // TODO(zfs): `zfs list -t snapshot -Hp`.
        Ok(Vec::new())
    }

    pub fn create_snapshot(
        &self,
        dataset_id: &str,
        req: CreateSnapshotRequest,
    ) -> ApiResult<Snapshot> {
        // TODO(zfs): `zfs snapshot [-r] <dataset>@<name>`.
        Ok(Snapshot {
            id: new_id(),
            name: format!("{dataset_id}@{}", req.name),
            dataset: dataset_id.to_string(),
            used_bytes: 0,
            created_at: now_ts(),
        })
    }

    pub fn clone_snapshot(
        &self,
        snapshot_id: &str,
        req: CloneSnapshotRequest,
    ) -> ApiResult<Dataset> {
        if req.target.trim().is_empty() {
            return Err(AppError::validation("target must not be empty"));
        }
        let _ = snapshot_id;
        // TODO(zfs): `zfs clone <snapshot> <target>`.
        Ok(Dataset {
            id: new_id(),
            name: req.target,
            kind: DatasetKind::Filesystem,
            used_bytes: 0,
            available_bytes: 0,
            mountpoint: None,
            compression: "lz4".to_string(),
            created_at: now_ts(),
        })
    }
}
