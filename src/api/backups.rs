//! Backup plans and restore workflows.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::backup::{
    BackupArtifact, BackupPlan, CreateBackupPlanRequest, RestoreBackupRequest,
    UpdateBackupPlanRequest,
};
use daygleve_schema::operations::OperationRecord;
use serde::Deserialize;

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/backups/plans", get(list_plans).post(create_plan))
        .route(
            "/backups/plans/{id}",
            get(get_plan).patch(update_plan).delete(delete_plan),
        )
        .route("/backups/plans/{id}/run", post(run_plan))
        .route("/backups/artifacts", get(list_artifacts))
        .route("/backups/artifacts/{id}/restore", post(restore))
}

async fn list_plans(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<BackupPlan>>> {
    user.require(Permission::BackupRead)?;
    Ok(Json(state.services.backup.list_plans().await?))
}

async fn create_plan(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateBackupPlanRequest>,
) -> ApiResult<(StatusCode, Json<BackupPlan>)> {
    user.require(Permission::BackupWrite)?;
    Ok((
        StatusCode::CREATED,
        Json(state.services.backup.create_plan(req).await?),
    ))
}

async fn get_plan(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<BackupPlan>> {
    user.require(Permission::BackupRead)?;
    Ok(Json(state.services.backup.get_plan(&id).await?))
}

async fn update_plan(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateBackupPlanRequest>,
) -> ApiResult<Json<BackupPlan>> {
    user.require(Permission::BackupWrite)?;
    Ok(Json(state.services.backup.update_plan(&id, req).await?))
}

async fn delete_plan(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::BackupWrite)?;
    state.services.backup.delete_plan(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn run_plan(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<(StatusCode, Json<OperationRecord>)> {
    user.require(Permission::BackupWrite)?;
    let operation = state
        .services
        .backup
        .enqueue_backup(
            &id,
            state.services.operations.clone(),
            state.services.clone(),
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(operation)))
}

#[derive(Debug, Deserialize)]
struct ArtifactQuery {
    plan_id: Option<String>,
}

async fn list_artifacts(
    user: AuthUser,
    State(state): State<AppState>,
    Query(query): Query<ArtifactQuery>,
) -> ApiResult<Json<Vec<BackupArtifact>>> {
    user.require(Permission::BackupRead)?;
    Ok(Json(
        state
            .services
            .backup
            .list_artifacts(query.plan_id.as_deref())
            .await?,
    ))
}

async fn restore(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<RestoreBackupRequest>,
) -> ApiResult<(StatusCode, Json<OperationRecord>)> {
    user.require(Permission::BackupWrite)?;
    let operation = state
        .services
        .backup
        .enqueue_restore(&id, req, state.services.operations.clone())
        .await?;
    Ok((StatusCode::ACCEPTED, Json(operation)))
}
