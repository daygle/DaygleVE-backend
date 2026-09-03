//! GPU passthrough endpoints.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::gpu::{BindGpuRequest, GpuDevice};

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/gpus", get(list))
        .route("/gpus/{pci_address}/bind", post(bind))
}

async fn list(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<Vec<GpuDevice>>> {
    user.require(Permission::GpuRead)?;
    Ok(Json(state.services.gpu.list().await?))
}

async fn bind(
    user: AuthUser,
    State(state): State<AppState>,
    Path(pci_address): Path<String>,
    Json(req): Json<BindGpuRequest>,
) -> ApiResult<(StatusCode, Json<GpuDevice>)> {
    user.require(Permission::GpuWrite)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(state.services.gpu.bind(&pci_address, req).await?),
    ))
}
