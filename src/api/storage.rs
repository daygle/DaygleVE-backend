//! ZFS storage endpoints: pools, datasets, snapshots and clones.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::storage::{
    CloneSnapshotRequest, CreateDatasetRequest, CreateSnapshotRequest, Dataset, Pool, Snapshot,
};

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/storage/pools", get(list_pools))
        .route("/storage/datasets", get(list_datasets).post(create_dataset))
        .route(
            "/storage/datasets/{id}/snapshots",
            get(list_snapshots).post(create_snapshot),
        )
        .route("/storage/snapshots/{id}/clone", post(clone_snapshot))
}

async fn list_pools(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<Vec<Pool>>> {
    user.require(Permission::StorageRead)?;
    Ok(Json(state.services.zfs.list_pools().await?))
}

async fn list_datasets(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<Dataset>>> {
    user.require(Permission::StorageRead)?;
    Ok(Json(state.services.zfs.list_datasets().await?))
}

async fn create_dataset(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateDatasetRequest>,
) -> ApiResult<(StatusCode, Json<Dataset>)> {
    user.require(Permission::StorageWrite)?;
    Ok((
        StatusCode::CREATED,
        Json(state.services.zfs.create_dataset(req).await?),
    ))
}

async fn list_snapshots(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<Snapshot>>> {
    user.require(Permission::StorageRead)?;
    Ok(Json(state.services.zfs.list_snapshots(&id).await?))
}

async fn create_snapshot(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateSnapshotRequest>,
) -> ApiResult<(StatusCode, Json<Snapshot>)> {
    user.require(Permission::StorageWrite)?;
    Ok((
        StatusCode::CREATED,
        Json(state.services.zfs.create_snapshot(&id, req).await?),
    ))
}

async fn clone_snapshot(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CloneSnapshotRequest>,
) -> ApiResult<(StatusCode, Json<Dataset>)> {
    user.require(Permission::StorageWrite)?;
    Ok((
        StatusCode::CREATED,
        Json(state.services.zfs.clone_snapshot(&id, req).await?),
    ))
}
