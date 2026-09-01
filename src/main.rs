//! DaygleVE backend — the hypervisor engine and REST API server.
//!
//! This binary wires configuration, the shared application state, the service
//! layer (KVM/QEMU, LXC, ZFS, networking, GPU, metrics, auth) and the
//! versioned Axum router together, then serves the API.
//!
//! Repo boundary: this crate is the *only* place hypervisor/host logic lives.
//! It imports every API type from `daygleve-schema` and contains no frontend
//! code.

mod api;
mod auth;
mod config;
mod error;
mod services;
mod state;

use std::net::SocketAddr;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::config::Config;
use crate::state::AppState;

#[tokio::main]
async fn main() -> anyhow_lite::Result<()> {
    // Structured logging; level via `RUST_LOG` (defaults to info).
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Config::from_env();
    let addr: SocketAddr = config.listen_addr;

    let state = AppState::new(config);
    let app = api::router(state);

    tracing::info!(%addr, "DaygleVE backend listening");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow_lite::err(format!("bind {addr}: {e}")))?;
    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow_lite::err(format!("serve: {e}")))?;

    Ok(())
}

/// Minimal local error-boxing helper so we don't pull in the full `anyhow`
/// crate just for `main`'s return type.
mod anyhow_lite {
    pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
    pub fn err(msg: String) -> Box<dyn std::error::Error> {
        Box::<dyn std::error::Error + Send + Sync>::from(msg)
    }
}
