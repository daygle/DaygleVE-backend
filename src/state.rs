//! Shared application state handed to every request handler.

use std::sync::Arc;
use std::time::Instant;

use crate::config::Config;
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
    pub fn new(config: Config) -> Self {
        let config = Arc::new(config);
        let services = Arc::new(Services::new(config.clone()));
        Self {
            config,
            services,
            started_at: Instant::now(),
        }
    }

    /// Seconds since the process started.
    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}
