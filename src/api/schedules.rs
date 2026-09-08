//! Scheduled power-action endpoints.
//!
//! A schedule fires a power action against one guest, so it is gated by the
//! same power permission as the target (`VmPower` / `LxcPower`). The target
//! guest must exist at creation time; membership is fixed thereafter.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::schedule::{
    CreatePowerScheduleRequest, PowerSchedule, ScheduleTarget, UpdatePowerScheduleRequest,
};
use serde::Deserialize;

use crate::auth::AuthUser;
use crate::error::{ApiResult, AppError};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/schedules", get(list).post(create))
        .route("/schedules/{id}", get(get_one).patch(update).delete(delete))
}

/// Permission a schedule requires, chosen by the guest it targets.
fn power_permission(kind: ScheduleTarget) -> Permission {
    match kind {
        ScheduleTarget::Vm => Permission::VmPower,
        ScheduleTarget::Lxc => Permission::LxcPower,
    }
}

/// Confirm the target guest exists before a schedule can point at it.
async fn ensure_target_exists(
    state: &AppState,
    kind: ScheduleTarget,
    target_id: &str,
) -> ApiResult<()> {
    match kind {
        ScheduleTarget::Vm => {
            state.services.kvm.get(target_id).await?;
        }
        ScheduleTarget::Lxc => {
            state.services.lxc.get(target_id).await?;
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    target_kind: Option<ScheduleTarget>,
    target_id: Option<String>,
}

async fn list(
    user: AuthUser,
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<PowerSchedule>>> {
    // Reading schedules needs read access to whichever guest kinds are being
    // asked for; require both by default, or just the filtered kind.
    match q.target_kind {
        Some(ScheduleTarget::Vm) => user.require(Permission::VmRead)?,
        Some(ScheduleTarget::Lxc) => user.require(Permission::LxcRead)?,
        None => {
            user.require(Permission::VmRead)?;
            user.require(Permission::LxcRead)?;
        }
    }
    let schedules = match (q.target_kind, q.target_id) {
        (Some(kind), Some(id)) => state.services.schedules.list_for(kind, &id).await?,
        _ => state.services.schedules.list().await?,
    };
    Ok(Json(schedules))
}

async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreatePowerScheduleRequest>,
) -> ApiResult<(StatusCode, Json<PowerSchedule>)> {
    user.require(power_permission(req.target_kind))?;
    ensure_target_exists(&state, req.target_kind, &req.target_id).await?;
    let created = state.services.schedules.create(req).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_one(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<PowerSchedule>> {
    let schedule = state.services.schedules.get(&id).await?;
    user.require(match schedule.target_kind {
        ScheduleTarget::Vm => Permission::VmRead,
        ScheduleTarget::Lxc => Permission::LxcRead,
    })?;
    Ok(Json(schedule))
}

async fn update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdatePowerScheduleRequest>,
) -> ApiResult<Json<PowerSchedule>> {
    let existing = state.services.schedules.get(&id).await?;
    user.require(power_permission(existing.target_kind))?;
    Ok(Json(state.services.schedules.update(&id, req).await?))
}

async fn delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let existing = state.services.schedules.get(&id).await?;
    user.require(power_permission(existing.target_kind))?;
    if !state.services.schedules.delete(&id).await? {
        return Err(AppError::not_found(format!("schedule {id}")));
    }
    Ok(StatusCode::NO_CONTENT)
}
