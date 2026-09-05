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
    /// Directory holding installer/live ISO images offered as VM install media.
    /// `DAYGLEVE_ISO_DIR`, default `<state_dir>/isos`.
    pub iso_dir: PathBuf,
    /// Parent directory under which network shares (NFS/CIFS) are mounted, one
    /// subdirectory per share id. `DAYGLEVE_MOUNTS_DIR`, default
    /// `<state_dir>/mounts`.
    pub mounts_dir: PathBuf,
    /// Root directory for local ZFS send-stream backups. `DAYGLEVE_BACKUP_DIR`,
    /// default `<state_dir>/backups`.
    pub backup_dir: PathBuf,
    /// Lifetime of an issued bearer token, in seconds. `DAYGLEVE_TOKEN_TTL_SECS`,
    /// default 12 hours.
    pub token_ttl_secs: u64,
    /// Password for the seeded `admin` account, from `DAYGLEVE_ADMIN_PASSWORD`.
    /// When unset, the backend generates a random initial password on first
    /// boot (there is deliberately no built-in default password).
    pub admin_password: Option<String>,
    /// PEM certificate chain for HTTPS. `DAYGLEVE_TLS_CERT`. TLS is enabled only
    /// when both this and `tls_key` are set; otherwise the API is served over
    /// plain HTTP (front it with a TLS-terminating proxy in that case).
    pub tls_cert: Option<PathBuf>,
    /// PEM private key for HTTPS. `DAYGLEVE_TLS_KEY`.
    pub tls_key: Option<PathBuf>,
    /// Unix socket of the root-owned host broker. `DAYGLEVE_BROKER_SOCKET`.
    /// When set, every allowlisted host command, PCI sysfs write, and LXC
    /// config write is delegated to the broker process instead of being
    /// performed directly — the privilege split from the security plan.
    /// When unset (dev hosts), the backend executes host tools directly.
    pub broker_socket: Option<PathBuf>,
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

        let iso_dir = std::env::var("DAYGLEVE_ISO_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| state_dir.join("isos"));

        let mounts_dir = std::env::var("DAYGLEVE_MOUNTS_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| state_dir.join("mounts"));

        let backup_dir = std::env::var("DAYGLEVE_BACKUP_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| state_dir.join("backups"));

        let token_ttl_secs = std::env::var("DAYGLEVE_TOKEN_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(12 * 60 * 60);

        let admin_password = std::env::var("DAYGLEVE_ADMIN_PASSWORD")
            .ok()
            .filter(|s| !s.is_empty());

        let tls_cert = std::env::var("DAYGLEVE_TLS_CERT")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        let tls_key = std::env::var("DAYGLEVE_TLS_KEY")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        let broker_socket = std::env::var("DAYGLEVE_BROKER_SOCKET")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        Self {
            listen_addr,
            cors_origins,
            default_pool,
            web_root,
            state_dir,
            iso_dir,
            mounts_dir,
            backup_dir,
            token_ttl_secs,
            admin_password,
            tls_cert,
            tls_key,
            broker_socket,
        }
    }

    /// Resolved TLS material when *both* a certificate and key are configured.
    pub fn tls(&self) -> Option<(&std::path::Path, &std::path::Path)> {
        match (&self.tls_cert, &self.tls_key) {
            (Some(cert), Some(key)) => Some((cert.as_path(), key.as_path())),
            _ => None,
        }
    }
}
