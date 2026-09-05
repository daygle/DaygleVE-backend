//! Durable operations, asynchronous jobs, and host reconciliation.
//!
//! Every mutating handler records its lifecycle before touching the host. Phase
//! 1C adds a small worker boundary for jobs that should not run inside an HTTP
//! request (currently the reconciliation scan), while preserving the existing
//! synchronous mutation contracts.

use std::future::Future;
use std::sync::Arc;

use daygleve_schema::operations::{
    OperationRecord, OperationStatus, QuarantineDecision, QuarantineStatus, ReconcileRequest,
    ReconciliationFinding, ReconciliationFindingKind, ReconciliationMode,
    ReconciliationQuarantineRecord,
};

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
    quarantine: JsonStore,
    _config: Arc<Config>,
}

impl OperationService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            store: JsonStore::new(&config.state_dir, "operations"),
            quarantine: JsonStore::new(&config.state_dir, "reconciliation_quarantine"),
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

    /// Enqueue a reconciliation pass. Dry runs only inventory and persist
    /// structured findings. Repair runs require a successful dry-run approval
    /// and only perform explicitly marked non-destructive repairs; unmanaged
    /// host resources are quarantined instead of silently adopted or deleted.
    pub(crate) async fn enqueue_reconciliation(
        self: &Arc<Self>,
        services: Arc<Services>,
        request: ReconcileRequest,
    ) -> ApiResult<OperationRecord> {
        let approved_findings = if request.mode == ReconciliationMode::Repair {
            let approval_id = request.approval_id.as_deref().ok_or_else(|| {
                AppError::validation("repair requires approval_id from a dry run")
            })?;
            let approval = self.get(approval_id).await?;
            if approval.kind != "host.reconcile"
                || approval.status != OperationStatus::Succeeded
                || approval.reconciliation_mode != Some(ReconciliationMode::DryRun)
                || approval.findings.is_none()
            {
                return Err(AppError::conflict(
                    "approval_id must reference a completed reconciliation dry run",
                ));
            }
            approval.findings.unwrap_or_default()
        } else {
            Vec::new()
        };
        if request.mode == ReconciliationMode::Repair && !request.quarantine_unmanaged {
            return Err(AppError::validation(
                "repair requires quarantine_unmanaged=true; unmanaged resources are never auto-adopted",
            ));
        }
        let mode = request.mode;
        let record = self
            .enqueue(
            "host.reconcile",
            Some("node"),
            None,
            move |operations, handle| async move {
                operations.set_reconciliation_mode(&handle.id, mode).await?;
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
                operations
                    .update_progress(&handle.id, 90, Some("checking for drift"))
                    .await?;
                let findings = if mode == ReconciliationMode::DryRun {
                    Self::detect_drift(&services).await?
                } else {
                    approved_findings
                };
                operations.set_findings(&handle.id, findings.clone()).await?;
                operations.persist_unmanaged_findings(&findings).await?;
                if mode == ReconciliationMode::Repair {
                    operations
                        .update_progress(&handle.id, 94, Some("applying approved repairs"))
                        .await?;
                    Self::repair_findings(&services, &operations, &findings).await?;
                }
                let mut msg = format!(
                    "reconciled {vms} VMs, {containers} containers, {datasets} datasets, {bridges} bridges, {shares} shares, and {gpus} GPUs"
                );
                if !findings.is_empty() {
                    msg.push_str(&format!("; {} drift findings", findings.len()));
                }
                if mode == ReconciliationMode::Repair {
                    msg.push_str("; approved non-destructive repairs applied and unmanaged resources quarantined");
                }
                Ok(Some(msg))
            },
            )
            .await?;
        self.get(&record.id).await
    }

    async fn repair_findings(
        services: &Arc<Services>,
        operations: &OperationService,
        findings: &[ReconciliationFinding],
    ) -> ApiResult<()> {
        for finding in findings {
            if finding.kind == ReconciliationFindingKind::UnmanagedHost {
                if let Some(host_id) = &finding.host_id {
                    operations
                        .quarantine(&finding.resource_type, host_id, &finding.message)
                        .await?;
                }
                continue;
            }
            if !finding.repairable || finding.destructive {
                continue;
            }
            match finding.resource_type.as_str() {
                "vm" => {
                    services
                        .kvm
                        .repair_missing_from_host(&finding.resource_id)
                        .await?
                }
                "container" => {
                    services
                        .lxc
                        .repair_missing_from_host(&finding.resource_id)
                        .await?
                }
                "bridge" => {
                    services
                        .network
                        .repair_missing_from_host(&finding.resource_id)
                        .await?
                }
                "vlan" => {
                    services
                        .network
                        .repair_vlan_from_host(&finding.resource_id)
                        .await?
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Compare persisted records to live host state and return structured,
    /// auditable discrepancies. This function never changes host or store state.
    async fn detect_drift(services: &Arc<Services>) -> ApiResult<Vec<ReconciliationFinding>> {
        let mut findings: Vec<ReconciliationFinding> = Vec::new();

        // VMs.
        let (vm_missing_host, vm_missing_store) = services.kvm.reconcile_with_host().await?;
        for item in vm_missing_host {
            findings.push(ReconciliationFinding {
                resource_type: "vm".to_string(),
                resource_id: item.clone(),
                host_id: None,
                kind: ReconciliationFindingKind::MissingFromHost,
                message: format!("VM record is missing from libvirt: {item}"),
                repairable: true,
                destructive: false,
            });
        }
        for host_id in vm_missing_store {
            findings.push(ReconciliationFinding {
                resource_type: "vm".to_string(),
                resource_id: host_id.clone(),
                host_id: Some(host_id.clone()),
                kind: ReconciliationFindingKind::UnmanagedHost,
                message: format!("VM {host_id} exists in libvirt but is not tracked"),
                repairable: false,
                destructive: false,
            });
        }

        // Containers.
        let (ct_missing_host, ct_missing_store) = services.lxc.reconcile_with_host().await?;
        for name in ct_missing_host {
            findings.push(ReconciliationFinding {
                resource_type: "container".to_string(),
                resource_id: name.clone(),
                host_id: None,
                kind: ReconciliationFindingKind::MissingFromHost,
                message: format!(
                    "container {name} is missing from LXC; restore or import is required"
                ),
                repairable: false,
                destructive: true,
            });
        }
        for host_id in ct_missing_store {
            findings.push(ReconciliationFinding {
                resource_type: "container".to_string(),
                resource_id: host_id.clone(),
                host_id: Some(host_id.clone()),
                kind: ReconciliationFindingKind::UnmanagedHost,
                message: format!("container {host_id} exists in LXC but is not tracked"),
                repairable: false,
                destructive: false,
            });
        }

        // Network.
        let (net_missing_host, net_missing_store) = services.network.reconcile_with_host().await?;
        for resource_id in net_missing_host {
            findings.push(ReconciliationFinding {
                resource_type: if resource_id.starts_with("vlan:") {
                    "vlan"
                } else {
                    "bridge"
                }
                .to_string(),
                resource_id: resource_id
                    .strip_prefix("vlan:")
                    .unwrap_or(&resource_id)
                    .to_string(),
                host_id: None,
                kind: ReconciliationFindingKind::MissingFromHost,
                message: format!("network resource {resource_id} is missing from host"),
                repairable: true,
                destructive: false,
            });
        }
        for host_id in net_missing_store {
            findings.push(ReconciliationFinding {
                resource_type: "bridge".to_string(),
                resource_id: host_id.clone(),
                host_id: Some(host_id.clone()),
                kind: ReconciliationFindingKind::UnmanagedHost,
                message: format!("network resource {host_id} exists on host but is not tracked"),
                repairable: false,
                destructive: false,
            });
        }

        Ok(findings)
    }

    async fn set_reconciliation_mode(&self, id: &str, mode: ReconciliationMode) -> ApiResult<()> {
        let mut record = self.get(id).await?;
        record.reconciliation_mode = Some(mode);
        self.store.put(&record.id, &record).await
    }

    pub(crate) async fn set_findings(
        &self,
        id: &str,
        findings: Vec<ReconciliationFinding>,
    ) -> ApiResult<()> {
        let mut record = self.get(id).await?;
        record.findings = Some(findings);
        record.drift = record
            .findings
            .as_ref()
            .filter(|items| !items.is_empty())
            .map(|items| {
                items
                    .iter()
                    .map(|item| item.message.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            });
        self.store.put(&record.id, &record).await
    }

    pub(crate) async fn quarantine(
        &self,
        resource_type: &str,
        host_id: &str,
        message: &str,
    ) -> ApiResult<ReconciliationQuarantineRecord> {
        if let Some(existing) = self
            .quarantine
            .list::<ReconciliationQuarantineRecord>()
            .await?
            .into_iter()
            .find(|item| {
                item.status == QuarantineStatus::Pending
                    && item.resource_type == resource_type
                    && item.host_id == host_id
            })
        {
            return Ok(existing);
        }
        let record = ReconciliationQuarantineRecord {
            id: new_id(),
            resource_type: resource_type.to_string(),
            host_id: host_id.to_string(),
            message: message.to_string(),
            status: QuarantineStatus::Pending,
            created_at: now_ts(),
            decided_at: None,
            decided_by: None,
            decision_message: None,
        };
        self.quarantine.put(&record.id, &record).await?;
        Ok(record)
    }

    async fn persist_unmanaged_findings(
        &self,
        findings: &[ReconciliationFinding],
    ) -> ApiResult<()> {
        for finding in findings {
            if finding.kind == ReconciliationFindingKind::UnmanagedHost {
                if let Some(host_id) = finding.host_id.as_deref() {
                    self.quarantine(&finding.resource_type, host_id, &finding.message)
                        .await?;
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn list_quarantine(&self) -> ApiResult<Vec<ReconciliationQuarantineRecord>> {
        let mut records: Vec<ReconciliationQuarantineRecord> = self.quarantine.list().await?;
        records.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(records)
    }

    /// Apply an explicit quarantine decision and persist the decision as an
    /// audit record. Unmanaged resources are never adopted implicitly by repair.
    pub(crate) async fn decide_quarantine(
        &self,
        services: &Arc<Services>,
        id: &str,
        decision: QuarantineDecision,
        actor: &str,
        message: Option<&str>,
    ) -> ApiResult<ReconciliationQuarantineRecord> {
        let mut record: ReconciliationQuarantineRecord = self
            .quarantine
            .get(id)
            .await?
            .ok_or_else(|| AppError::not_found("quarantine record not found"))?;
        if record.status != QuarantineStatus::Pending {
            return Err(AppError::conflict(
                "quarantine record already has a decision",
            ));
        }
        match decision {
            QuarantineDecision::Adopt => match record.resource_type.as_str() {
                "bridge" => {
                    services.network.adopt_bridge(&record.host_id).await?;
                    record.status = QuarantineStatus::Adopted;
                }
                _ => {
                    return Err(AppError::validation(
                        "this resource type requires an explicit import workflow before adoption",
                    ));
                }
            },
            QuarantineDecision::Release => {
                record.status = QuarantineStatus::Released;
            }
        }
        record.decided_at = Some(now_ts());
        record.decided_by = Some(actor.to_string());
        record.decision_message = message.map(str::to_string);
        self.quarantine.put(&record.id, &record).await?;
        Ok(record)
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
            reconciliation_mode: None,
            progress_pct: None,
            resource_type: resource_type.map(str::to_string),
            resource_id: resource_id.map(str::to_string),
            result_id: None,
            drift: None,
            findings: None,
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
            backup_dir: dir.join("backups"),
            token_ttl_secs: 3600,
            admin_password: Some("test-password-generated-at-runtime".into()),
            tls_cert: None,
            tls_key: None,
            broker_socket: None,
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
