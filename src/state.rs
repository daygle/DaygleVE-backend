//! Shared application state handed to every request handler.

use std::sync::Arc;
use std::time::Instant;

use crate::config::Config;
use daygleve_schema::operations::{ReconcileRequest, ReconciliationMode};

use crate::services::Services;

/// Cheap-to-clone handle to everything a handler needs: configuration, the
/// service layer, and process start time (for uptime reporting).
#[derive(Clone)]
pub struct AppState {
    /// Shared configuration; read by the API layer (CORS) and handlers.
    pub config: Arc<Config>,
    pub services: Arc<Services>,
    pub started_at: Instant,
}

impl AppState {
    /// Build the shared state and load persisted data (user accounts) from the
    /// record store, seeding an initial admin on first boot.
    pub async fn new(config: Config) -> crate::error::ApiResult<Self> {
        let config = Arc::new(config);
        let services = Arc::new(Services::new(config.clone()));
        services.auth.load_or_seed().await?;
        let recovered = services.operations.recover_interrupted().await?;
        if recovered.interrupted > 0 {
            tracing::warn!(
                interrupted = recovered.interrupted,
                "startup recovered interrupted operations; inspect the operations endpoint"
            );
        }
        services.backup.start_scheduler(services.clone());
        let startup_job = services
            .operations
            .enqueue_reconciliation(
                services.clone(),
                ReconcileRequest {
                    mode: ReconciliationMode::DryRun,
                    approval_id: None,
                    quarantine_unmanaged: true,
                },
            )
            .await?;
        tracing::info!(operation_id = %startup_job.id, "queued startup host reconciliation");
        Ok(Self {
            config,
            services,
            started_at: Instant::now(),
        })
    }

    /// Seconds since the process started.
    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}
