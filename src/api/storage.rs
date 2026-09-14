//! ZFS storage endpoints: pools, datasets, snapshots and clones.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::operations::OperationRecord;
use daygleve_schema::share::{CreateShareRequest, NetworkShare};
use daygleve_schema::storage::{
    CloneSnapshotRequest, CreateDatasetRequest, CreatePoolRequest, CreateSnapshotRequest, Dataset,
    Pool, RawDisk, SmartReport, Snapshot, WipeDiskRequest,
};

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/storage/pools", get(list_pools).post(create_pool))
        .route("/storage/disks", get(list_disks))
        .route("/storage/disks/smart", get(smart_disk))
        .route("/storage/disks/wipe", post(wipe_disk))
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

async fn create_pool(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreatePoolRequest>,
) -> ApiResult<(StatusCode, Json<OperationRecord>)> {
    user.require(Permission::StorageWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let actor = user.0.user.id.clone();
    let record = operations
        .enqueue(
            "storage.create_pool",
            Some("pool"),
            None,
            Some(&actor),
            move |ops, handle| async move {
                ops.update_progress(&handle.id, 10, Some("creating ZFS pool"))
                    .await?;
                let pool = services.zfs.create_pool(req).await?;
                ops.set_result_id(&handle.id, &pool.name).await?;
                Ok(Some(format!("created pool {}", pool.name)))
            },
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(record)))
}

async fn list_disks(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<RawDisk>>> {
    user.require(Permission::StorageRead)?;
    Ok(Json(state.services.zfs.list_raw_disks().await?))
}

#[derive(Debug, serde::Deserialize)]
struct DiskPathQuery {
    path: String,
}

async fn smart_disk(
    user: AuthUser,
    State(state): State<AppState>,
    Query(query): Query<DiskPathQuery>,
) -> ApiResult<Json<SmartReport>> {
    user.require(Permission::StorageRead)?;
    Ok(Json(state.services.zfs.smart_report(&query.path).await?))
}

async fn wipe_disk(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<WipeDiskRequest>,
) -> ApiResult<StatusCode> {
    user.require(Permission::StorageWrite)?;
    state.services.zfs.wipe_disk(req).await?;
    Ok(StatusCode::NO_CONTENT)
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
) -> ApiResult<(StatusCode, Json<OperationRecord>)> {
    user.require(Permission::StorageWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let actor = user.0.user.id.clone();
    let record = operations
        .enqueue(
            "storage.create_dataset",
            Some("dataset"),
            None,
            Some(&actor),
            move |ops, handle| async move {
                ops.update_progress(&handle.id, 10, Some("creating dataset"))
                    .await?;
                let dataset = services.zfs.create_dataset(req).await?;
                ops.set_result_id(&handle.id, &dataset.id).await?;
                Ok(Some(format!("created dataset {}", dataset.name)))
            },
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(record)))
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
) -> ApiResult<(StatusCode, Json<OperationRecord>)> {
    user.require(Permission::StorageWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let record = operations
        .enqueue(
            "storage.create_snapshot",
            Some("snapshot"),
            Some(&resource_id),
            Some(&actor),
            move |ops, handle| async move {
                ops.update_progress(&handle.id, 10, Some("snapshotting"))
                    .await?;
                let snapshot = services.zfs.create_snapshot(&id, req).await?;
                ops.set_result_id(&handle.id, &snapshot.id).await?;
                Ok(Some(format!("created snapshot {}", snapshot.name)))
            },
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(record)))
}

async fn clone_snapshot(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CloneSnapshotRequest>,
) -> ApiResult<(StatusCode, Json<OperationRecord>)> {
    user.require(Permission::StorageWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let record = operations
        .enqueue(
            "storage.clone_snapshot",
            Some("dataset"),
            Some(&resource_id),
            Some(&actor),
            move |ops, handle| async move {
                ops.update_progress(&handle.id, 10, Some("cloning snapshot"))
                    .await?;
                let dataset = services.zfs.clone_snapshot(&id, req).await?;
                ops.set_result_id(&handle.id, &dataset.id).await?;
                Ok(Some(format!("cloned dataset {}", dataset.name)))
            },
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(record)))
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
) -> ApiResult<(StatusCode, Json<OperationRecord>)> {
    user.require(Permission::StorageWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let actor = user.0.user.id.clone();
    let record = operations
        .enqueue(
            "storage.create_share",
            Some("share"),
            None,
            Some(&actor),
            move |ops, handle| async move {
                ops.update_progress(&handle.id, 10, Some("mounting share"))
                    .await?;
                let share = services.shares.create(req).await?;
                ops.set_result_id(&handle.id, &share.id).await?;
                Ok(Some(format!("mounted share {}", share.name)))
            },
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(record)))
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
    let actor = user.0.user.id.clone();
    operations
        .run(
            "storage.delete_share",
            Some("share"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.shares.delete(&id).await },
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
