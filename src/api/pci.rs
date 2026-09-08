//! General (non-GPU) PCI passthrough endpoints: inventory of attachable PCI
//! functions and the vfio bind step. Binding reuses the GPU service's `bind`
//! (the sysfs/vfio operation is identical regardless of device class); attach
//! itself happens through the VM create request (`pci_devices`).

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::gpu::{BindGpuRequest, GpuDevice};
use daygleve_schema::pci::PciDevice;

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/pci-devices", get(list))
        .route("/pci-devices/{pci_address}/bind", post(bind))
}

async fn list(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<Vec<PciDevice>>> {
    user.require(Permission::GpuRead)?;
    Ok(Json(state.services.pci.list().await?))
}

/// Bind a PCI function to `vfio-pci` so it can be passed through. Reuses the GPU
/// service's bind (same operation for any device class); returns the bound
/// device as a `GpuDevice` shell - only its `available`/driver state matters
/// here.
async fn bind(
    user: AuthUser,
    State(state): State<AppState>,
    Path(pci_address): Path<String>,
    Json(req): Json<BindGpuRequest>,
) -> ApiResult<Json<GpuDevice>> {
    user.require(Permission::GpuWrite)?;
    Ok(Json(state.services.gpu.bind(&pci_address, req).await?))
}
