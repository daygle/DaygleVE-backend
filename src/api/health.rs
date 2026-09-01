//! Health/readiness endpoint (unauthenticated).

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use daygleve_schema::common::{HealthStatus, API_VERSION};

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/health", get(health))
}

async fn health(State(state): State<AppState>) -> Json<HealthStatus> {
    Json(HealthStatus {
        healthy: true,
        version: env!("CARGO_PKG_VERSION").to_string(),
        api_version: API_VERSION.to_string(),
        uptime_seconds: state.uptime_seconds(),
    })
}
