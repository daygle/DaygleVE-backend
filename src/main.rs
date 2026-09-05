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
mod broker;
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
    if let Some(socket) = &config.broker_socket {
        tracing::info!(socket = %socket.display(), "root-owned host broker is configured");
    } else {
        tracing::warn!("DAYGLEVE_BROKER_SOCKET is unset; privileged host operations use the direct development path");
    }
    let addr: SocketAddr = config.listen_addr;

    let state = AppState::new(config.clone())
        .await
        .map_err(|e| anyhow_lite::err(format!("initialize state: {}", e.message())))?;
    let app = api::router(state);

    // Loudly flag a half-configured TLS setup: exactly one of cert/key set is
    // almost always a mistake that would otherwise silently serve plaintext.
    if config.tls_cert.is_some() != config.tls_key.is_some() {
        tracing::error!(
            "only one of DAYGLEVE_TLS_CERT/DAYGLEVE_TLS_KEY is set — TLS is DISABLED and the server will serve plaintext HTTP; set BOTH (or neither)"
        );
    }

    // Serve HTTPS when a certificate + key are configured, otherwise plain HTTP
    // (intended to sit behind a TLS-terminating proxy in that case).
    if let Some((cert, key)) = config.tls() {
        // rustls 0.23 needs an explicit process-level crypto provider.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .map_err(|e| anyhow_lite::err(format!("load TLS cert/key: {e}")))?;
        tracing::info!(%addr, "DaygleVE backend listening (HTTPS)");
        axum_server::bind_rustls(addr, tls)
            .serve(app.into_make_service())
            .await
            .map_err(|e| anyhow_lite::err(format!("serve https: {e}")))?;
    } else {
        tracing::warn!(%addr, "DaygleVE backend listening (HTTP; set DAYGLEVE_TLS_CERT/DAYGLEVE_TLS_KEY or front with a TLS proxy)");
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| anyhow_lite::err(format!("bind {addr}: {e}")))?;
        axum::serve(listener, app)
            .await
            .map_err(|e| anyhow_lite::err(format!("serve: {e}")))?;
    }

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
