//! ZFS storage endpoints: pools, datasets, snapshots and clones.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::share::{CreateShareRequest, NetworkShare};
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
        .route("/storage/shares", get(list_shares).post(create_share))
        .route("/storage/shares/{id}", axum::routing::delete(delete_share))
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
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let dataset = operations
        .run(
            "storage.create_dataset",
            Some("dataset"),
            None,
            move || async move { operation_services.zfs.create_dataset(req).await },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(dataset)))
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
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let snapshot = operations
        .run(
            "storage.create_snapshot",
            Some("snapshot"),
            Some(&resource_id),
            move || async move { operation_services.zfs.create_snapshot(&id, req).await },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(snapshot)))
}

async fn clone_snapshot(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CloneSnapshotRequest>,
) -> ApiResult<(StatusCode, Json<Dataset>)> {
    user.require(Permission::StorageWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let dataset = operations
        .run(
            "storage.clone_snapshot",
            Some("dataset"),
            Some(&resource_id),
            move || async move { operation_services.zfs.clone_snapshot(&id, req).await },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(dataset)))
}

// --- Network shares (NFS/CIFS) ---

async fn list_shares(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<NetworkShare>>> {
    user.require(Permission::StorageRead)?;
    Ok(Json(state.services.shares.list().await?))
}

async fn create_share(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateShareRequest>,
) -> ApiResult<(StatusCode, Json<NetworkShare>)> {
    user.require(Permission::StorageWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let share = operations
        .run(
            "storage.create_share",
            Some("share"),
            None,
            move || async move { operation_services.shares.create(req).await },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(share)))
}

async fn delete_share(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::StorageWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    operations
        .run(
            "storage.delete_share",
            Some("share"),
            Some(&resource_id),
            move || async move { operation_services.shares.delete(&id).await },
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
