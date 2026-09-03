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
    /// Directory for DaygleVE's own persistent state (VM/container/bridge
    /// records). `DAYGLEVE_STATE_DIR`, default `/var/lib/daygleve`.
    pub state_dir: PathBuf,
    /// Lifetime of an issued bearer token, in seconds. `DAYGLEVE_TOKEN_TTL_SECS`,
    /// default 12 hours.
    pub token_ttl_secs: u64,
    /// Password for the seeded `admin` account. `DAYGLEVE_ADMIN_PASSWORD`,
    /// default `daygleve` (a warning is logged until it is overridden).
    pub admin_password: String,
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

        let state_dir = std::env::var("DAYGLEVE_STATE_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/daygleve"));

        let token_ttl_secs = std::env::var("DAYGLEVE_TOKEN_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(12 * 60 * 60);

        let admin_password =
            std::env::var("DAYGLEVE_ADMIN_PASSWORD").unwrap_or_else(|_| "daygleve".to_string());

        Self {
            listen_addr,
            cors_origins,
            default_pool,
            web_root,
            state_dir,
            token_ttl_secs,
            admin_password,
        }
    }
}
