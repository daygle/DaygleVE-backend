//! Local ZFS stream backup and restore service.
//!
//! Backups are immutable ZFS send streams stored below the configured
//! `DAYGLEVE_BACKUP_DIR`. The service never accepts an arbitrary host path from
//! a client: destinations are relative, validated components below that root.
//! Guest sources are resolved from DaygleVE records before any host command is
//! started.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use daygleve_schema::backup::{
    BackupArtifact, BackupFile, BackupPlan, BackupSourceType, CreateBackupPlanRequest,
    RestoreBackupRequest, UpdateBackupPlanRequest,
};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::command;
use crate::services::operations::OperationService;
use crate::services::store::JsonStore;
use crate::services::{ensure_safe_id, ensure_safe_zfs_dataset, new_id, now_ts, Services};

const MIN_INTERVAL_SECS: u64 = 60;
const MAX_RETENTION: u32 = 3650;

pub struct BackupService {
    plans: JsonStore,
    artifacts: JsonStore,
    config: Arc<Config>,
    running: Arc<Mutex<HashSet<String>>>,
}

impl BackupService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            plans: JsonStore::new(&config.state_dir, "backup_plans"),
            artifacts: JsonStore::new(&config.state_dir, "backup_artifacts"),
            config,
            running: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub async fn list_plans(&self) -> ApiResult<Vec<BackupPlan>> {
        let mut plans: Vec<BackupPlan> = self.plans.list().await?;
        plans.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(plans)
    }

    pub async fn get_plan(&self, id: &str) -> ApiResult<BackupPlan> {
        ensure_safe_id(id)?;
        self.plans
            .get(id)
            .await?
            .ok_or_else(|| AppError::not_found("backup plan not found"))
    }

    pub async fn create_plan(&self, req: CreateBackupPlanRequest) -> ApiResult<BackupPlan> {
        validate_plan_request(&req)?;
        ensure_safe_id(&req.name)?;
        let plans = self.list_plans().await?;
        if plans
            .iter()
            .any(|p| p.name.eq_ignore_ascii_case(req.name.trim()))
        {
            return Err(AppError::conflict(
                "a backup plan with that name already exists",
            ));
        }
        let now = now_ts();
        let next = req.interval_secs.map(|secs| add_seconds(&now, secs));
        let plan = BackupPlan {
            id: new_id(),
            name: req.name.trim().to_string(),
            source_type: req.source_type,
            source_id: req.source_id.trim().to_string(),
            destination: req.destination.trim().to_string(),
            interval_secs: req.interval_secs,
            retention_count: req.retention_count,
            verify: req.verify,
            enabled: req.enabled,
            created_at: now,
            updated_at: None,
            last_run_at: None,
            next_run_at: next,
        };
        self.plans.put(&plan.id, &plan).await?;
        Ok(plan)
    }

    pub async fn update_plan(
        &self,
        id: &str,
        req: UpdateBackupPlanRequest,
    ) -> ApiResult<BackupPlan> {
        let mut plan = self.get_plan(id).await?;
        if let Some(interval) = req.interval_secs {
            validate_interval(Some(interval))?;
            plan.interval_secs = Some(interval);
            plan.next_run_at = Some(add_seconds(&now_ts(), interval));
        }
        if let Some(retention) = req.retention_count {
            validate_retention(retention)?;
            plan.retention_count = retention;
        }
        if let Some(verify) = req.verify {
            plan.verify = verify;
        }
        if let Some(enabled) = req.enabled {
            plan.enabled = enabled;
            if enabled && plan.interval_secs.is_some() && plan.next_run_at.is_none() {
                plan.next_run_at = plan.interval_secs.map(|s| add_seconds(&now_ts(), s));
            }
        }
        plan.updated_at = Some(now_ts());
        self.plans.put(&plan.id, &plan).await?;
        Ok(plan)
    }

    pub async fn delete_plan(&self, id: &str) -> ApiResult<()> {
        let _ = self.get_plan(id).await?;
        if self.running.lock().await.contains(id) {
            return Err(AppError::conflict("backup plan is currently running"));
        }
        self.plans.delete(id).await?;
        Ok(())
    }

    pub async fn list_artifacts(&self, plan_id: Option<&str>) -> ApiResult<Vec<BackupArtifact>> {
        let mut artifacts: Vec<BackupArtifact> = self.artifacts.list().await?;
        if let Some(plan_id) = plan_id {
            artifacts.retain(|a| a.plan_id == plan_id);
        }
        artifacts.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(artifacts)
    }

    pub async fn get_artifact(&self, id: &str) -> ApiResult<BackupArtifact> {
        ensure_safe_id(id)?;
        self.artifacts
            .get(id)
            .await?
            .ok_or_else(|| AppError::not_found("backup artifact not found"))
    }

    /// Start a manual backup and return the durable operation record.
    pub async fn enqueue_backup(
        self: &Arc<Self>,
        plan_id: &str,
        operations: Arc<OperationService>,
        services: Arc<Services>,
    ) -> ApiResult<daygleve_schema::operations::OperationRecord> {
        let plan = self.get_plan(plan_id).await?;
        self.enqueue_backup_for_plan(plan, operations, services)
            .await
    }

    async fn enqueue_backup_for_plan(
        self: &Arc<Self>,
        plan: BackupPlan,
        operations: Arc<OperationService>,
        services: Arc<Services>,
    ) -> ApiResult<daygleve_schema::operations::OperationRecord> {
        {
            let mut running = self.running.lock().await;
            if !running.insert(plan.id.clone()) {
                return Err(AppError::conflict(
                    "a backup for this plan is already running",
                ));
            }
        }
        let plan_id = plan.id.clone();
        let resource_id = plan_id.clone();
        let worker = Arc::clone(self);
        let plan_for_worker = plan.clone();
        let cleanup_id = plan_id.clone();
        let op = operations
            .enqueue(
                "backup.run",
                Some("backup_plan"),
                Some(&resource_id),
                move |ops, handle| async move {
                    let result = worker
                        .run_backup(&plan_for_worker, &services, &ops, &handle.id)
                        .await;
                    worker.running.lock().await.remove(&cleanup_id);
                    let artifact = result?;
                    Ok(Some(format!(
                        "created backup {} ({} bytes)",
                        artifact.id, artifact.total_size_bytes
                    )))
                },
            )
            .await;
        if op.is_err() {
            self.running.lock().await.remove(plan_id.as_str());
        }
        op
    }

    /// Restore an artifact as a durable asynchronous operation. Dataset restore
    /// writes the stream into a newly created target dataset; it will not destroy
    /// or replace an existing target unless `force` is true.
    pub async fn enqueue_restore(
        self: &Arc<Self>,
        artifact_id: &str,
        req: RestoreBackupRequest,
        operations: Arc<OperationService>,
    ) -> ApiResult<daygleve_schema::operations::OperationRecord> {
        let artifact = self.get_artifact(artifact_id).await?;
        if !artifact.verified {
            return Err(AppError::conflict(
                "this artifact was not verified; verify it before restoring",
            ));
        }
        if artifact.files.len() != 1 {
            return Err(AppError::validation(
                "restore currently supports one-dataset artifacts only",
            ));
        }
        let target = match (artifact.source_type, req.target_id.as_deref()) {
            (BackupSourceType::Dataset, Some(target)) => target.trim().to_string(),
            (BackupSourceType::Dataset, None) => artifact.source_id.clone(),
            (_, Some(target)) => target.trim().to_string(),
            (_, None) => {
                return Err(AppError::validation(
                    "target_id is required when restoring a VM or container backup",
                ))
            }
        };
        ensure_safe_zfs_dataset(&target)?;
        let force = req.force;
        let file = artifact.files[0].clone();
        let worker = Arc::clone(self);
        let operation_target = target.clone();
        operations
            .enqueue(
                "backup.restore",
                Some("dataset"),
                Some(&operation_target),
                move |ops, handle| async move {
                    ops.update_progress(&handle.id, 10, Some("verifying backup file"))
                        .await?;
                    worker.verify_file(&file).await?;
                    ops.update_progress(&handle.id, 35, Some("restoring ZFS stream"))
                        .await?;
                    worker.restore_file(&file, &target, force).await?;
                    Ok(Some(format!("restored {} to {}", file.snapshot, target)))
                },
            )
            .await
    }

    /// Launch the in-process scheduler. Scheduling is persisted in each plan,
    /// and manual execution remains available even when the scheduler is off.
    pub fn start_scheduler(self: &Arc<Self>, services: Arc<Services>) {
        let worker = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            loop {
                tick.tick().await;
                let now = now_ts();
                let plans = match worker.list_plans().await {
                    Ok(plans) => plans,
                    Err(error) => {
                        tracing::error!(error = %error.message(), "backup scheduler could not read plans");
                        continue;
                    }
                };
                for plan in plans {
                    if !plan.enabled || plan.interval_secs.is_none() {
                        continue;
                    }
                    if plan
                        .next_run_at
                        .as_deref()
                        .is_some_and(|at| at <= now.as_str())
                    {
                        match worker
                            .enqueue_backup_for_plan(
                                plan,
                                services.operations.clone(),
                                services.clone(),
                            )
                            .await
                        {
                            Ok(record) => {
                                tracing::info!(operation_id = %record.id, "scheduled backup queued")
                            }
                            Err(error) if error.message().contains("already running") => {}
                            Err(error) => {
                                tracing::error!(error = %error.message(), "scheduled backup could not start")
                            }
                        }
                    }
                }
            }
        });
    }

    async fn run_backup(
        &self,
        plan: &BackupPlan,
        services: &Arc<Services>,
        operations: &OperationService,
        operation_id: &str,
    ) -> ApiResult<BackupArtifact> {
        let datasets = self.resolve_sources(plan, services).await?;
        if datasets.is_empty() {
            return Err(AppError::validation("backup source contains no datasets"));
        }
        let artifact_id = new_id();
        let tag = format!("daygleve-backup-{}", artifact_id.replace('-', ""));
        tokio::fs::create_dir_all(&self.config.backup_dir)
            .await
            .map_err(|e| AppError::internal(format!("create backup root: {e}")))?;
        let destination = safe_destination(&self.config.backup_dir, &plan.destination)?;
        tokio::fs::create_dir_all(&destination)
            .await
            .map_err(|e| AppError::internal(format!("create backup destination: {e}")))?;
        let root = self
            .config
            .backup_dir
            .canonicalize()
            .map_err(|e| AppError::internal(format!("resolve backup root: {e}")))?;
        let resolved_destination = destination
            .canonicalize()
            .map_err(|e| AppError::internal(format!("resolve backup destination: {e}")))?;
        if !resolved_destination.starts_with(&root) {
            return Err(AppError::validation(
                "backup destination escapes backup root",
            ));
        }
        let mut files = Vec::new();
        let mut created_snapshots = Vec::new();
        let result = async {
            for (index, dataset) in datasets.iter().enumerate() {
                operations
                    .update_progress(
                        operation_id,
                        ((index as u8) * 70 / datasets.len() as u8).max(5),
                        Some("creating backup snapshot"),
                    )
                    .await?;
                let snapshot = format!("{dataset}@{tag}");
                command::run_ok("zfs", &["snapshot", &snapshot]).await?;
                created_snapshots.push(snapshot.clone());
                let path = destination.join(format!("{}-{}.zfs", artifact_id, index));
                let size = self.send_to_file(&snapshot, &path).await?;
                let sha = sha256_file(&path).await?;
                if plan.verify {
                    operations
                        .update_progress(operation_id, 75, Some("verifying backup checksum"))
                        .await?;
                    self.verify_checksum(&path, &sha).await?;
                }
                files.push(BackupFile {
                    dataset: (*dataset).to_string(),
                    snapshot: snapshot.clone(),
                    path: path.to_string_lossy().into_owned(),
                    size_bytes: size,
                    sha256: sha,
                });
            }
            let artifact = BackupArtifact {
                id: artifact_id.clone(),
                plan_id: plan.id.clone(),
                source_type: plan.source_type,
                source_id: plan.source_id.clone(),
                created_at: now_ts(),
                total_size_bytes: files.iter().map(|f| f.size_bytes).sum(),
                verified: plan.verify,
                files,
            };
            self.artifacts.put(&artifact.id, &artifact).await?;
            self.apply_retention(plan).await?;
            Ok(artifact)
        }
        .await;
        for snapshot in created_snapshots {
            let _ = command::run_ok("zfs", &["destroy", &snapshot]).await;
        }
        let mut current = self.get_plan(&plan.id).await?;
        let now = now_ts();
        if result.is_ok() {
            current.last_run_at = Some(now.clone());
        }
        // Advance the schedule after every attempt, not only after success. A
        // failed host operation must not be retried every scheduler tick.
        current.next_run_at = current.interval_secs.map(|s| add_seconds(&now, s));
        self.plans.put(&current.id, &current).await?;
        result
    }

    async fn resolve_sources(
        &self,
        plan: &BackupPlan,
        services: &Arc<Services>,
    ) -> ApiResult<Vec<String>> {
        match plan.source_type {
            BackupSourceType::Dataset => {
                ensure_safe_zfs_dataset(&plan.source_id)?;
                Ok(vec![plan.source_id.clone()])
            }
            BackupSourceType::Vm => {
                let vm = services.kvm.get(&plan.source_id).await?;
                vm.disks
                    .iter()
                    .map(|disk| ensure_safe_zfs_dataset(disk.dataset.trim()).map(str::to_string))
                    .collect()
            }
            BackupSourceType::Container => {
                let ct = services.lxc.get(&plan.source_id).await?;
                ensure_safe_zfs_dataset(&ct.rootfs_dataset).map(|s| vec![s.to_string()])
            }
        }
    }

    async fn send_to_file(&self, snapshot: &str, path: &Path) -> ApiResult<u64> {
        let args = ["send", "-p", snapshot];
        command::stream_to_file("zfs", &args, path).await
    }

    async fn restore_file(&self, file: &BackupFile, target: &str, force: bool) -> ApiResult<()> {
        ensure_safe_zfs_dataset(target)?;
        let exists = command::run_optional("zfs", &["list", "-H", "-o", "name", target]).await?;
        if exists.is_some() && !force {
            return Err(AppError::conflict(
                "restore target already exists; set force to replace it",
            ));
        }
        if exists.is_some() && force {
            command::run_ok("zfs", &["destroy", "-r", target]).await?;
        }
        let args = ["receive", "-F", target];
        command::stream_from_file("zfs", &args, Path::new(&file.path)).await
    }

    async fn verify_file(&self, file: &BackupFile) -> ApiResult<()> {
        let actual = sha256_file(Path::new(&file.path)).await?;
        if actual != file.sha256 {
            return Err(AppError::conflict("backup checksum verification failed"));
        }
        Ok(())
    }

    async fn verify_checksum(&self, path: &Path, expected: &str) -> ApiResult<()> {
        let actual = sha256_file(path).await?;
        if actual != expected {
            return Err(AppError::internal(
                "backup checksum changed during verification",
            ));
        }
        Ok(())
    }

    async fn apply_retention(&self, plan: &BackupPlan) -> ApiResult<()> {
        let mut artifacts = self.list_artifacts(Some(&plan.id)).await?;
        if artifacts.len() <= plan.retention_count as usize {
            return Ok(());
        }
        for artifact in artifacts.drain(plan.retention_count as usize..) {
            for file in artifact.files {
                let _ = tokio::fs::remove_file(file.path).await;
            }
            self.artifacts.delete(&artifact.id).await?;
        }
        Ok(())
    }
}

fn validate_plan_request(req: &CreateBackupPlanRequest) -> ApiResult<()> {
    if req.name.trim().is_empty() || req.name.trim().len() > 64 {
        return Err(AppError::validation(
            "backup plan name must be 1..=64 characters",
        ));
    }
    if req.source_id.trim().is_empty() {
        return Err(AppError::validation("backup source_id must not be empty"));
    }
    ensure_safe_id(req.name.trim())?;
    validate_interval(req.interval_secs)?;
    validate_retention(req.retention_count)?;
    validate_destination(&req.destination)?;
    match req.source_type {
        BackupSourceType::Dataset => {
            ensure_safe_zfs_dataset(req.source_id.trim())?;
        }
        BackupSourceType::Vm | BackupSourceType::Container => {
            ensure_safe_id(req.source_id.trim())?;
        }
    }
    Ok(())
}

fn validate_interval(value: Option<u64>) -> ApiResult<()> {
    if value.is_some_and(|secs| secs < MIN_INTERVAL_SECS) {
        return Err(AppError::validation(
            "backup interval must be at least 60 seconds",
        ));
    }
    Ok(())
}

fn validate_retention(value: u32) -> ApiResult<()> {
    if value == 0 || value > MAX_RETENTION {
        return Err(AppError::validation(format!(
            "retention_count must be 1..={MAX_RETENTION}"
        )));
    }
    Ok(())
}

fn validate_destination(value: &str) -> ApiResult<()> {
    if value.trim().is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value.len() > 128
    {
        return Err(AppError::validation(
            "destination must be a relative backup directory",
        ));
    }
    if value
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'/'))
    {
        return Err(AppError::validation(
            "destination contains invalid path components",
        ));
    }
    Ok(())
}

fn safe_destination(root: &Path, relative: &str) -> ApiResult<PathBuf> {
    validate_destination(relative)?;
    let path = root.join(relative);
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(AppError::validation("destination escapes backup root"));
    }
    Ok(path)
}

fn add_seconds(timestamp: &str, secs: u64) -> String {
    DateTime::parse_from_rfc3339(timestamp)
        .ok()
        .map(|dt| {
            (dt.with_timezone(&Utc) + chrono::Duration::seconds(secs.min(i64::MAX as u64) as i64))
                .to_rfc3339()
        })
        .unwrap_or_else(now_ts)
}

async fn sha256_file(path: &Path) -> ApiResult<String> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| AppError::internal(format!("open {}: {e}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .await
            .map_err(|e| AppError::internal(format!("read {}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_validation_blocks_escape() {
        assert!(validate_destination("nas/nightly").is_ok());
        assert!(validate_destination("../outside").is_err());
        assert!(validate_destination("/etc").is_err());
        assert!(validate_destination("nas\\outside").is_err());
    }

    #[test]
    fn policy_limits_are_enforced() {
        assert!(validate_interval(Some(60)).is_ok());
        assert!(validate_interval(Some(59)).is_err());
        assert!(validate_retention(1).is_ok());
        assert!(validate_retention(0).is_err());
    }
}
