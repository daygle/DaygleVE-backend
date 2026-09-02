//! HTTP API layer: router assembly and the versioned route tree.
//!
//! All routes are mounted under `/api/{API_VERSION}` (currently `/api/v1`),
//! matching the OpenAPI document in DaygleVE-schema. Handlers are thin: they
//! authenticate, authorize, delegate to a service, and serialise schema types.

mod containers;
mod gpus;
mod health;
mod metrics;
mod network;
mod storage;
mod vms;

pub mod auth;

use axum::Router;
use daygleve_schema::common::API_VERSION;
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Build the full application router.
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .merge(health::routes())
        .merge(auth::routes())
        .merge(vms::routes())
        .merge(containers::routes())
        .merge(storage::routes())
        .merge(network::routes())
        .merge(gpus::routes())
        .merge(metrics::routes());

    let cors = cors_layer(&state.config.cors_origins);

    let mut app = Router::new().nest(&format!("/api/{API_VERSION}"), api);

    // On the appliance, serve the prebuilt frontend SPA for every non-API path,
    // falling back to index.html so client-side routing works. In dev
    // (`DAYGLEVE_WEB_ROOT` unset) this is skipped and the SvelteKit dev server
    // serves the UI on its own port.
    if let Some(web_root) = &state.config.web_root {
        let index = web_root.join("index.html");
        let serve = ServeDir::new(web_root).fallback(ServeFile::new(index));
        app = app.fallback_service(serve);
        tracing::info!(web_root = %web_root.display(), "serving frontend assets");
    }

    app.layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}

/// Build the CORS layer. With no configured origins we fall back to a
/// permissive policy for local development; in production set
/// `DAYGLEVE_CORS_ORIGINS` to the frontend origin(s).
fn cors_layer(origins: &[String]) -> CorsLayer {
    if origins.is_empty() {
        return CorsLayer::permissive();
    }
    let parsed: Vec<_> = origins
        .iter()
        .filter_map(|o| o.parse::<axum::http::HeaderValue>().ok())
        .collect();
    CorsLayer::new().allow_origin(parsed)
}
