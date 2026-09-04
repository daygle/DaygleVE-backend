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
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = pci_address.clone();
    let device = operations
        .run(
            "gpu.bind",
            Some("gpu"),
            Some(&resource_id),
            move || async move { operation_services.gpu.bind(&pci_address, req).await },
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(device)))
}
