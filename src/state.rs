//! Shared application state handed to every request handler.

use std::sync::Arc;
use std::time::Instant;

use daygleve_schema::operations::{ReconcileRequest, ReconciliationMode};
use tokio::sync::Mutex;

use crate::config::Config;
use crate::services::login_throttle::LoginThrottle;
use crate::services::Services;

/// Cheap-to-clone handle to everything a handler needs: configuration, the
/// service layer, and process start time (for uptime reporting).
#[derive(Clone)]
pub struct AppState {
    /// Shared configuration; read by the API layer (CORS) and handlers.
    pub config: Arc<Config>,
    pub services: Arc<Services>,
    /// Brute-force resistance for the login endpoint: per-IP and per-account
    /// exponential backoff. Lock-guarded because penalties mutate on every
    /// failed login.
    pub login_throttle: Arc<Mutex<LoginThrottle>>,
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
        services.schedules.start_scheduler(services.clone());
        services
            .snapshot_schedules
            .start_scheduler(services.clone());
        // Persist per-VM and per-container samples independently of whether a
        // dashboard is connected. The loop is intentionally detached from the
        // request path and degrades gracefully on hosts without libvirt/LXC.
        {
            let services = services.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(15));
                loop {
                    tick.tick().await;
                    let vms = match services.kvm.list().await {
                        Ok(vms) => vms,
                        Err(error) => {
                            tracing::warn!(error = %error.message(), "guest metrics could not list VMs");
                            Vec::new()
                        }
                    };
                    let containers = match services.lxc.list().await {
                        Ok(containers) => containers,
                        Err(error) => {
                            tracing::warn!(error = %error.message(), "guest metrics could not list containers");
                            Vec::new()
                        }
                    };
                    if let Err(error) = services.metrics.collect_guests(&vms, &containers).await {
                        tracing::warn!(error = %error.message(), "guest metrics collection failed");
                    }
                    // Evaluate threshold alert rules against the fresh samples.
                    // Pool capacity comes straight from `zpool list`; a failure
                    // skips pool rules for the tick without blocking guest rules.
                    let pools = match services.zfs.list_pools().await {
                        Ok(pools) => pools
                            .iter()
                            .map(|p| (p.name.clone(), p.allocated_bytes, p.size_bytes))
                            .collect::<Vec<_>>(),
                        Err(_) => Vec::new(),
                    };
                    let (node_cpu_pct, node_memory_used, node_memory_total) = {
                        let node = services.metrics.node().await;
                        (
                            node.cpu_pct,
                            node.memory_used_bytes,
                            node.memory_total_bytes,
                        )
                    };
                    let vm_samples = services.metrics.current_guests();
                    let vm_metrics: Vec<_> = vm_samples
                        .iter()
                        .filter(|s| s.scope == daygleve_schema::metrics::MetricsScope::Vm)
                        .map(|s| s.metrics.clone())
                        .collect();
                    let lxc_metrics: Vec<_> = vm_samples
                        .iter()
                        .filter(|s| s.scope == daygleve_schema::metrics::MetricsScope::Lxc)
                        .map(|s| s.metrics.clone())
                        .collect();
                    let obs = crate::services::alerts::Observations {
                        vms: &vm_metrics,
                        containers: &lxc_metrics,
                        node_cpu_pct,
                        node_memory_used,
                        node_memory_total,
                        pools: &pools,
                    };
                    if let Err(error) = services.alerts.evaluate(&obs).await {
                        tracing::warn!(error = %error.message(), "alert evaluation failed");
                    }
                }
            });
        }
        // Bring up autostart VMs in the background so a slow guest boot never
        // blocks the API from starting to serve.
        {
            let services = services.clone();
            tokio::spawn(async move { services.kvm.start_autostart_vms().await });
        }
        let startup_job = services
            .operations
            .enqueue_reconciliation(
                services.clone(),
                ReconcileRequest {
                    mode: ReconciliationMode::DryRun,
                    approval_id: None,
                    quarantine_unmanaged: true,
                },
                None,
            )
            .await?;
        tracing::info!(operation_id = %startup_job.id, "queued startup host reconciliation");
        Ok(Self {
            config,
            services,
            login_throttle: Arc::new(Mutex::new(LoginThrottle::new())),
            started_at: Instant::now(),
        })
    }

    /// Seconds since the process started.
    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}
