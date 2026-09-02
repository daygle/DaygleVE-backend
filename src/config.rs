//! Runtime configuration, sourced from the environment.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Process configuration. Kept small and explicit; extend as subsystems grow.
#[derive(Debug, Clone)]
pub struct Config {
    /// Address the HTTP API binds to. `DAYGLEVE_LISTEN`, default `0.0.0.0:8080`.
    pub listen_addr: SocketAddr,
    /// Comma-separated allowed CORS origins. `DAYGLEVE_CORS_ORIGINS`.
    /// Empty means "reflect no cross-origin" (same-origin only).
    pub cors_origins: Vec<String>,
    /// Default ZFS pool new datasets are created under. `DAYGLEVE_ZPOOL`.
    pub default_pool: String,
    /// Directory of prebuilt frontend assets to serve as an SPA under `/`.
    /// `DAYGLEVE_WEB_ROOT`. When unset (dev) only the API is served and the
    /// SvelteKit dev server handles the UI. On the appliance this points at the
    /// bundled frontend build (e.g. `/usr/share/daygleve/web`).
    pub web_root: Option<PathBuf>,
}

impl Config {
    /// Build configuration from environment variables, applying defaults.
    pub fn from_env() -> Self {
        let listen_addr = std::env::var("DAYGLEVE_LISTEN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "0.0.0.0:8080".parse().expect("valid default addr"));

        let cors_origins = std::env::var("DAYGLEVE_CORS_ORIGINS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        let default_pool = std::env::var("DAYGLEVE_ZPOOL").unwrap_or_else(|_| "tank".to_string());

        let web_root = std::env::var("DAYGLEVE_WEB_ROOT")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        Self {
            listen_addr,
            cors_origins,
            default_pool,
            web_root,
        }
    }
}
