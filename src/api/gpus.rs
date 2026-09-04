//! GPU passthrough endpoints.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::gpu::{BindGpuRequest, GpuDevice};
use daygleve_schema::operations::OperationRecord;

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
) -> ApiResult<(StatusCode, Json<OperationRecord>)> {
    user.require(Permission::GpuWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let resource_id = pci_address.clone();
    let record = operations
        .enqueue(
            "gpu.bind",
            Some("gpu"),
            Some(&resource_id),
            move |ops, handle| async move {
                ops.update_progress(&handle.id, 10, Some("binding to vfio-pci"))
                    .await?;
                let device = services.gpu.bind(&pci_address, req).await?;
                ops.set_result_id(&handle.id, &device.pci_address).await?;
                Ok(Some(format!("bound GPU {}", device.pci_address)))
            },
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(record)))
}
