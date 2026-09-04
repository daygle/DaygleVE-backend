//! Durable operation journal and crash recovery.
//!
//! Mutating handlers record their lifecycle in `<state_dir>/operations` before
//! touching the host. If the backend exits between the host change and the
//! final record update, startup recovery marks the operation `needs_review`
//! instead of pretending it completed. The journal is intentionally small and
//! uses the same atomic JSON store as the resource records; a later phase can
//! move long-running operations to a worker queue without changing this
//! recovery contract.

use std::future::Future;
use std::sync::Arc;

use daygleve_schema::operations::{OperationRecord, OperationStatus};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::store::JsonStore;
use crate::services::{new_id, now_ts};

/// Handle retained by a mutating workflow while it runs.
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
    /// review. This is deliberately fail-closed: an unknown outcome is never
    /// reported as success.
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
    /// Journal-finalization failures are logged but do not change the host
    /// operation's result: the operation already happened, so returning a
    /// second error would make the API lie about the host state.
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

    /// List operation records, newest first.
    pub(crate) async fn list(&self) -> ApiResult<Vec<OperationRecord>> {
        let mut records: Vec<OperationRecord> = self.store.list().await?;
        records.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(records)
    }

    /// Begin a synchronous operation. The record is durable before the caller
    /// performs any privileged host action.
    pub(crate) async fn begin(
        &self,
        kind: &str,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
    ) -> ApiResult<OperationHandle> {
        if kind.trim().is_empty() {
            return Err(AppError::validation("operation kind must not be empty"));
        }
        let now = now_ts();
        let record = OperationRecord {
            id: new_id(),
            kind: kind.to_string(),
            status: OperationStatus::Running,
            resource_type: resource_type.map(str::to_string),
            resource_id: resource_id.map(str::to_string),
            created_at: now.clone(),
            started_at: Some(now),
            finished_at: None,
            message: None,
            error: None,
        };
        let id = record.id.clone();
        self.store.put(&id, &record).await?;
        Ok(OperationHandle { id })
    }

    /// Mark an operation successful. A journal update failure is returned so the
    /// caller can log it, but callers should not roll back an already-successful
    /// host operation solely because its audit record could not be updated.
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

    /// Mark an operation failed with a sanitized, human-readable error.
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
        record.message = message.map(str::to_string);
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
        let _ = std::fs::remove_dir_all(dir);
    }
}
