//! Scheduled-snapshot endpoints.
//!
//! A snapshot schedule captures snapshots of one guest, so it is gated by the
//! same write permission as taking a snapshot manually (`VmWrite` / `LxcWrite`).
//! The target guest is fixed at creation and must exist.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::schedule::ScheduleTarget;
use daygleve_schema::snapshot_schedule::{
    CreateSnapshotScheduleRequest, SnapshotSchedule, UpdateSnapshotScheduleRequest,
};
use serde::Deserialize;

use crate::auth::AuthUser;
use crate::error::{ApiResult, AppError};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/snapshot-schedules", get(list).post(create))
        .route(
            "/snapshot-schedules/{id}",
            get(get_one).patch(update).delete(delete),
        )
}

fn write_permission(kind: ScheduleTarget) -> Permission {
    match kind {
        ScheduleTarget::Vm => Permission::VmWrite,
        ScheduleTarget::Lxc => Permission::LxcWrite,
    }
}

fn read_permission(kind: ScheduleTarget) -> Permission {
    match kind {
        ScheduleTarget::Vm => Permission::VmRead,
        ScheduleTarget::Lxc => Permission::LxcRead,
    }
}

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
) -> ApiResult<Json<Vec<SnapshotSchedule>>> {
    match q.target_kind {
        Some(kind) => user.require(read_permission(kind))?,
        None => {
            user.require(Permission::VmRead)?;
            user.require(Permission::LxcRead)?;
        }
    }
    let schedules = match (q.target_kind, q.target_id) {
        (Some(kind), Some(id)) => {
            state
                .services
                .snapshot_schedules
                .list_for(kind, &id)
                .await?
        }
        _ => state.services.snapshot_schedules.list().await?,
    };
    Ok(Json(schedules))
}

async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateSnapshotScheduleRequest>,
) -> ApiResult<(StatusCode, Json<SnapshotSchedule>)> {
    user.require(write_permission(req.target_kind))?;
    ensure_target_exists(&state, req.target_kind, &req.target_id).await?;
    let created = state.services.snapshot_schedules.create(req).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_one(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<SnapshotSchedule>> {
    let schedule = state.services.snapshot_schedules.get(&id).await?;
    user.require(read_permission(schedule.target_kind))?;
    Ok(Json(schedule))
}

async fn update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateSnapshotScheduleRequest>,
) -> ApiResult<Json<SnapshotSchedule>> {
    let existing = state.services.snapshot_schedules.get(&id).await?;
    user.require(write_permission(existing.target_kind))?;
    Ok(Json(
        state.services.snapshot_schedules.update(&id, req).await?,
    ))
}

async fn delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let existing = state.services.snapshot_schedules.get(&id).await?;
    user.require(write_permission(existing.target_kind))?;
    if !state.services.snapshot_schedules.delete(&id).await? {
        return Err(AppError::not_found(format!("snapshot schedule {id}")));
    }
    Ok(StatusCode::NO_CONTENT)
}
