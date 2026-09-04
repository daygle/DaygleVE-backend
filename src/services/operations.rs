//! Durable operations, asynchronous jobs, and host reconciliation.
//!
//! Every mutating handler records its lifecycle before touching the host. Phase
//! 1C adds a small worker boundary for jobs that should not run inside an HTTP
//! request (currently the reconciliation scan), while preserving the existing
//! synchronous mutation contracts.

use std::future::Future;
use std::sync::Arc;

use daygleve_schema::operations::{OperationRecord, OperationStatus};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::store::JsonStore;
use crate::services::Services;
use crate::services::{new_id, now_ts};

/// Handle retained by a workflow while it runs.
#[derive(Debug, Clone)]
pub(crate) struct OperationHandle {
    pub id: String,
}

/// Summary emitted during startup recovery.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RecoverySummary {
    pub interrupted: usize,
}

pub struct OperationService {
    store: JsonStore,
    _config: Arc<Config>,
}

impl OperationService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            store: JsonStore::new(&config.state_dir, "operations"),
            _config: config,
        }
    }

    /// Mark operations that were active at the previous shutdown as requiring
    /// review. Unknown outcomes are never reported as success.
    pub async fn recover_interrupted(&self) -> ApiResult<RecoverySummary> {
        let mut summary = RecoverySummary::default();
        let records: Vec<OperationRecord> = self.store.list().await?;
        for mut record in records {
            if !matches!(
                record.status,
                OperationStatus::Queued | OperationStatus::Running
            ) {
                continue;
            }
            record.status = OperationStatus::NeedsReview;
            record.finished_at = Some(now_ts());
            record.message = Some(
                "backend stopped before the operation outcome was recorded; inspect host state"
                    .to_string(),
            );
            self.store.put(&record.id, &record).await?;
            summary.interrupted += 1;
        }
        Ok(summary)
    }

    /// Run a synchronous operation with a durable journal record around it.
    pub(crate) async fn run<T, F, Fut>(
        &self,
        kind: &str,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
        operation: F,
    ) -> ApiResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ApiResult<T>>,
    {
        let handle = self.begin(kind, resource_type, resource_id).await?;
        match operation().await {
            Ok(value) => {
                if let Err(error) = self
                    .succeed(&handle, resource_type, resource_id, None)
                    .await
                {
                    tracing::error!(
                        operation_id = %handle.id,
                        error = %error.message(),
                        "could not finalize successful operation journal record"
                    );
                }
                Ok(value)
            }
            Err(error) => {
                if let Err(journal_error) = self.fail(&handle, error.message()).await {
                    tracing::error!(
                        operation_id = %handle.id,
                        error = %journal_error.message(),
                        "could not finalize failed operation journal record"
                    );
                }
                Err(error)
            }
        }
    }

    /// Queue a job and return its durable record immediately. The worker starts
    /// after the queued record is persisted, so a crash between enqueue and
    /// execution is recoverable on the next boot.
    pub(crate) async fn enqueue<F, Fut>(
        self: &Arc<Self>,
        kind: &str,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
        operation: F,
    ) -> ApiResult<OperationRecord>
    where
        F: FnOnce(Arc<Self>, OperationHandle) -> Fut + Send + 'static,
        Fut: Future<Output = ApiResult<Option<String>>> + Send + 'static,
    {
        let (handle, record) = self.queue(kind, resource_type, resource_id).await?;
        let worker = Arc::clone(self);
        let record_resource_type = resource_type.map(str::to_string);
        let record_resource_id = resource_id.map(str::to_string);
        tokio::spawn(async move {
            if let Err(error) = worker.mark_running(&handle).await {
                tracing::error!(
                    operation_id = %handle.id,
                    error = %error.message(),
                    "could not mark asynchronous operation as running"
                );
                return;
            }

            match operation(Arc::clone(&worker), handle.clone()).await {
                Ok(message) => {
                    if let Err(error) = worker
                        .succeed(
                            &handle,
                            record_resource_type.as_deref(),
                            record_resource_id.as_deref(),
                            message.as_deref(),
                        )
                        .await
                    {
                        tracing::error!(
                            operation_id = %handle.id,
                            error = %error.message(),
                            "could not finalize asynchronous operation"
                        );
                    }
                }
                Err(error) => {
                    if let Err(journal_error) = worker.fail(&handle, error.message()).await {
                        tracing::error!(
                            operation_id = %handle.id,
                            error = %journal_error.message(),
                            "could not record asynchronous operation failure"
                        );
                    }
                }
            }
        });
        Ok(record)
    }

    /// Enqueue a read-only host inventory scan. Listing services overlay their
    /// live host state onto persisted records, making this an automatic
    /// reconciliation pass without risking an unsolicited host mutation.
    ///
    /// The scan also compares persisted records to live host state and reports
    /// drift findings (VMs/containers/bridges that exist in one but not the
    /// other). Drift is informational only — the scan never auto-corrects.
    pub(crate) async fn enqueue_reconciliation(
        self: &Arc<Self>,
        services: Arc<Services>,
    ) -> ApiResult<OperationRecord> {
        self.enqueue(
            "host.reconcile",
            Some("node"),
            None,
            move |operations, handle| async move {
                operations
                    .update_progress(&handle.id, 5, Some("scanning virtual machines"))
                    .await?;
                let vms = services.kvm.list().await?.len();

                operations
                    .update_progress(&handle.id, 25, Some("scanning containers"))
                    .await?;
                let containers = services.lxc.list().await?.len();

                operations
                    .update_progress(&handle.id, 45, Some("scanning storage"))
                    .await?;
                let datasets = services.zfs.list_datasets().await?.len();

                operations
                    .update_progress(&handle.id, 65, Some("scanning network"))
                    .await?;
                let bridges = services.network.list_bridges().await?.len();
                let shares = services.shares.list().await?.len();

                operations
                    .update_progress(&handle.id, 85, Some("scanning passthrough devices"))
                    .await?;
                let gpus = services.gpu.list().await?.len();

                // Phase 2: drift detection — compare persisted records to live state.
                operations
                    .update_progress(&handle.id, 90, Some("checking for drift"))
                    .await?;
                let drift = Self::detect_drift(
                    &services,
                    &operations.store,
                )
                .await?;

                let mut msg = format!(
                    "reconciled {vms} VMs, {containers} containers, {datasets} datasets, {bridges} bridges, {shares} shares, and {gpus} GPUs"
                );
                if !drift.is_empty() {
                    msg.push_str(&format!(
                        "; drift: {drift}"
                    ));
                }
                Ok(Some(msg))
            },
        )
        .await
    }

    /// Compare persisted records to live host state and return a human-readable
    /// summary of discrepancies. Read-only: never modifies the host or store.
    async fn detect_drift(services: &Arc<Services>, store: &JsonStore) -> ApiResult<String> {
        let mut findings: Vec<String> = Vec::new();

        // VMs.
        let stored_vm_ids: std::collections::HashSet<String> = store
            .list::<daygleve_schema::vm::Vm>()
            .await?
            .into_iter()
            .map(|vm| vm.id)
            .collect();
        let (vm_missing_host, vm_missing_store) =
            services.kvm.reconcile_with_host(&stored_vm_ids).await?;
        if !vm_missing_host.is_empty() {
            findings.push(format!(
                "{} VMs missing from libvirt: {}",
                vm_missing_host.len(),
                vm_missing_host.join(", ")
            ));
        }
        if !vm_missing_store.is_empty() {
            findings.push(format!(
                "{} VMs in libvirt but not in store: {}",
                vm_missing_store.len(),
                vm_missing_store.join(", ")
            ));
        }

        // Containers.
        let stored_ct_ids: std::collections::HashSet<String> = store
            .list::<daygleve_schema::lxc::Lxc>()
            .await?
            .into_iter()
            .map(|ct| ct.id)
            .collect();
        let (ct_missing_host, ct_missing_store) =
            services.lxc.reconcile_with_host(&stored_ct_ids).await?;
        if !ct_missing_host.is_empty() {
            findings.push(format!(
                "{} containers missing from lxc: {}",
                ct_missing_host.len(),
                ct_missing_host.join(", ")
            ));
        }
        if !ct_missing_store.is_empty() {
            findings.push(format!(
                "{} containers in lxc but not in store: {}",
                ct_missing_store.len(),
                ct_missing_store.join(", ")
            ));
        }

        // Network.
        let mut stored_net_ids: std::collections::HashSet<String> = store
            .list::<daygleve_schema::network::Bridge>()
            .await?
            .into_iter()
            .map(|b| b.id)
            .collect();
        let vlans: Vec<daygleve_schema::network::Vlan> = store.list().await?;
        stored_net_ids.extend(vlans.into_iter().map(|v| v.id));

        let (net_missing_host, net_missing_store) = services
            .network
            .reconcile_with_host(&stored_net_ids)
            .await?;
        if !net_missing_host.is_empty() {
            findings.push(format!(
                "{} network resources missing from host: {}",
                net_missing_host.len(),
                net_missing_host.join(", ")
            ));
        }
        if !net_missing_store.is_empty() {
            findings.push(format!(
                "{} network resources on host but not in store: {}",
                net_missing_store.len(),
                net_missing_store.join(", ")
            ));
        }

        Ok(findings.join("; "))
    }

    /// List operation records, newest first.
    pub(crate) async fn list(&self) -> ApiResult<Vec<OperationRecord>> {
        let mut records: Vec<OperationRecord> = self.store.list().await?;
        records.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(records)
    }

    /// Read one operation record for polling.
    pub(crate) async fn get(&self, id: &str) -> ApiResult<OperationRecord> {
        self.store
            .get(id)
            .await?
            .ok_or_else(|| AppError::not_found("operation not found"))
    }

    /// Update progress for an active asynchronous job.
    pub(crate) async fn update_progress(
        &self,
        id: &str,
        progress_pct: u8,
        message: Option<&str>,
    ) -> ApiResult<()> {
        let mut record = self.get(id).await?;
        if matches!(
            record.status,
            OperationStatus::Succeeded
                | OperationStatus::Failed
                | OperationStatus::Cancelled
                | OperationStatus::NeedsReview
        ) {
            return Ok(());
        }
        record.progress_pct = Some(progress_pct.min(100));
        if let Some(message) = message {
            record.message = Some(message.to_string());
        }
        self.store.put(&record.id, &record).await
    }

    /// Begin a synchronous operation. The record is durable before host work.
    pub(crate) async fn begin(
        &self,
        kind: &str,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
    ) -> ApiResult<OperationHandle> {
        let (handle, _) = self
            .create_record(kind, OperationStatus::Running, resource_type, resource_id)
            .await?;
        Ok(handle)
    }

    async fn queue(
        &self,
        kind: &str,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
    ) -> ApiResult<(OperationHandle, OperationRecord)> {
        self.create_record(kind, OperationStatus::Queued, resource_type, resource_id)
            .await
    }

    async fn create_record(
        &self,
        kind: &str,
        status: OperationStatus,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
    ) -> ApiResult<(OperationHandle, OperationRecord)> {
        if kind.trim().is_empty() {
            return Err(AppError::validation("operation kind must not be empty"));
        }
        let now = now_ts();
        let started_at = (status == OperationStatus::Running).then(|| now.clone());
        let record = OperationRecord {
            id: new_id(),
            kind: kind.to_string(),
            status,
            progress_pct: None,
            resource_type: resource_type.map(str::to_string),
            resource_id: resource_id.map(str::to_string),
            result_id: None,
            drift: None,
            created_at: now,
            started_at,
            finished_at: None,
            message: None,
            error: None,
        };
        let id = record.id.clone();
        self.store.put(&id, &record).await?;
        Ok((OperationHandle { id }, record))
    }

    async fn mark_running(&self, handle: &OperationHandle) -> ApiResult<()> {
        let mut record = self.get(&handle.id).await?;
        if record.status != OperationStatus::Queued {
            return Ok(());
        }
        record.status = OperationStatus::Running;
        record.started_at = Some(now_ts());
        record.progress_pct = Some(0);
        self.store.put(&record.id, &record).await
    }

    /// Mark an operation successful.
    pub(crate) async fn succeed(
        &self,
        handle: &OperationHandle,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
        message: Option<&str>,
    ) -> ApiResult<()> {
        self.finish(
            handle,
            OperationStatus::Succeeded,
            resource_type,
            resource_id,
            message,
            None,
        )
        .await
    }

    /// Mark an operation failed with a human-readable error.
    pub(crate) async fn fail(&self, handle: &OperationHandle, error: &str) -> ApiResult<()> {
        self.finish(
            handle,
            OperationStatus::Failed,
            None,
            None,
            None,
            Some(error),
        )
        .await
    }

    /// Set the result_id on a completed or running operation.
    pub(crate) async fn set_result_id(&self, id: &str, result_id: &str) -> ApiResult<()> {
        let mut record = self.get(id).await?;
        record.result_id = Some(result_id.to_string());
        self.store.put(&record.id, &record).await
    }

    async fn finish(
        &self,
        handle: &OperationHandle,
        status: OperationStatus,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
        message: Option<&str>,
        error: Option<&str>,
    ) -> ApiResult<()> {
        let mut record = self
            .store
            .get::<OperationRecord>(&handle.id)
            .await?
            .ok_or_else(|| AppError::not_found("operation record not found"))?;
        record.status = status;
        if resource_type.is_some() {
            record.resource_type = resource_type.map(str::to_string);
        }
        if resource_id.is_some() {
            record.resource_id = resource_id.map(str::to_string);
        }
        record.finished_at = Some(now_ts());
        record.progress_pct = match status {
            OperationStatus::Succeeded => Some(100),
            _ => record.progress_pct,
        };
        record.message = message.map(str::to_string).or(record.message);
        record.error = error.map(str::to_string);
        self.store.put(&record.id, &record).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(dir: &std::path::Path) -> Arc<Config> {
        Arc::new(Config {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            cors_origins: vec![],
            default_pool: "tank".into(),
            web_root: None,
            state_dir: dir.to_path_buf(),
            iso_dir: dir.join("isos"),
            mounts_dir: dir.join("mounts"),
            token_ttl_secs: 3600,
            admin_password: Some("test-password-generated-at-runtime".into()),
            tls_cert: None,
            tls_key: None,
        })
    }

    #[tokio::test]
    async fn interrupted_operations_are_marked_for_review() {
        let dir = std::env::temp_dir().join(format!("daygleve-operations-test-{}", new_id()));
        let service = OperationService::new(test_config(&dir));
        let handle = service.begin("vm.create", Some("vm"), None).await.unwrap();

        let summary = service.recover_interrupted().await.unwrap();
        assert_eq!(summary.interrupted, 1);
        let records = service.list().await.unwrap();
        assert_eq!(records[0].id, handle.id);
        assert_eq!(records[0].status, OperationStatus::NeedsReview);
        assert!(records[0].finished_at.is_some());

        let second = service.recover_interrupted().await.unwrap();
        assert_eq!(second.interrupted, 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn completed_operations_are_not_recovered() {
        let dir = std::env::temp_dir().join(format!("daygleve-operations-test-{}", new_id()));
        let service = OperationService::new(test_config(&dir));
        let handle = service
            .begin("network.create_bridge", Some("bridge"), None)
            .await
            .unwrap();
        service
            .succeed(&handle, Some("bridge"), Some("br-1"), None)
            .await
            .unwrap();

        let summary = service.recover_interrupted().await.unwrap();
        assert_eq!(summary.interrupted, 0);
        let records = service.list().await.unwrap();
        assert_eq!(records[0].status, OperationStatus::Succeeded);
        assert_eq!(records[0].resource_id.as_deref(), Some("br-1"));
        assert_eq!(records[0].progress_pct, Some(100));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn queued_jobs_run_in_the_background_and_report_progress() {
        let dir = std::env::temp_dir().join(format!("daygleve-operations-test-{}", new_id()));
        let service = Arc::new(OperationService::new(test_config(&dir)));
        let queued = service
            .enqueue(
                "test.job",
                Some("node"),
                None,
                |operations, handle| async move {
                    operations
                        .update_progress(&handle.id, 50, Some("halfway"))
                        .await?;
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    Ok(Some("finished".to_string()))
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            queued.status,
            OperationStatus::Queued | OperationStatus::Running
        ));

        for _ in 0..20 {
            let record = service.get(&queued.id).await.unwrap();
            if record.status == OperationStatus::Succeeded {
                assert_eq!(record.progress_pct, Some(100));
                assert_eq!(record.message.as_deref(), Some("finished"));
                let _ = std::fs::remove_dir_all(dir);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("background job did not finish");
    }
}
