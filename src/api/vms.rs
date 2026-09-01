//! Virtual-machine endpoints. Each handler authorizes via [`AuthUser::require`]
//! before delegating to the KVM service.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::vm::{
    ConsoleTicket, CreateVmRequest, UpdateVmRequest, Vm, VmPowerRequest, VmSummary,
};

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/vms", get(list).post(create))
        .route("/vms/{id}", get(get_one).patch(update).delete(delete))
        .route("/vms/{id}/power", post(power))
        .route("/vms/{id}/console", post(console))
}

async fn list(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<Vec<VmSummary>>> {
    user.require(Permission::VmRead)?;
    Ok(Json(state.services.kvm.list()))
}

async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateVmRequest>,
) -> ApiResult<(StatusCode, Json<Vm>)> {
    user.require(Permission::VmWrite)?;
    let vm = state.services.kvm.create(req)?;
    Ok((StatusCode::CREATED, Json(vm)))
}

async fn get_one(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Vm>> {
    user.require(Permission::VmRead)?;
    Ok(Json(state.services.kvm.get(&id)?))
}

async fn update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateVmRequest>,
) -> ApiResult<Json<Vm>> {
    user.require(Permission::VmWrite)?;
    Ok(Json(state.services.kvm.update(&id, req)?))
}

async fn delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::VmWrite)?;
    state.services.kvm.delete(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn power(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<VmPowerRequest>,
) -> ApiResult<(StatusCode, Json<Vm>)> {
    user.require(Permission::VmPower)?;
    let vm = state.services.kvm.power(&id, req.action)?;
    Ok((StatusCode::ACCEPTED, Json(vm)))
}

async fn console(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<ConsoleTicket>> {
    user.require(Permission::VmPower)?;
    Ok(Json(state.services.kvm.console(&id)?))
}
