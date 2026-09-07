//! USB passthrough inventory endpoint. Attaching a device to a VM happens
//! through the VM create request (`usb_devices`); this only lists what the host
//! offers, gated by the same passthrough-inventory permission as GPUs.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::usb::UsbDevice;

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/usb-devices", get(list))
}

async fn list(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<Vec<UsbDevice>>> {
    user.require(Permission::GpuRead)?;
    Ok(Json(state.services.usb.list().await?))
}
