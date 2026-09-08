//! Local media-library endpoints: upload, list and delete install ISOs and LXC
//! container-template tarballs kept on the node's own storage.
//!
//! Uploads stream the raw request body to disk and can be many gigabytes, so
//! they are mounted on a separate router ([`upload_routes`]) that is **not**
//! wrapped by the small global request-body limit the JSON API uses. The size
//! is bounded instead by `Config::max_upload_bytes`, enforced as the body is
//! streamed. Listing and deletion are ordinary small requests and live on
//! [`routes`].

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::storage_file::{
    ImportDiskImageRequest, ImportDiskImageResponse, StorageFile, StorageFileKind,
};

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

/// Small (limited-body) library routes: list and delete.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/storage/isos", get(list_isos))
        .route("/storage/isos/{name}", delete(delete_iso))
        .route("/storage/ct-templates", get(list_ct_templates))
        .route("/storage/ct-templates/{name}", delete(delete_ct_template))
        .route("/storage/disk-images", get(list_disk_images))
        .route("/storage/disk-images/{name}", delete(delete_disk_image))
        .route("/storage/disk-images/import", post(import_disk_image))
}

/// Large-body upload routes, mounted outside the global request-body limit.
pub fn upload_routes() -> Router<AppState> {
    Router::new()
        .route("/storage/isos/{name}", post(upload_iso))
        .route("/storage/ct-templates/{name}", post(upload_ct_template))
        .route("/storage/disk-images/{name}", post(upload_disk_image))
}

async fn list_isos(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<StorageFile>>> {
    user.require(Permission::StorageRead)?;
    Ok(Json(
        state.services.library.list(StorageFileKind::Iso).await?,
    ))
}

async fn list_ct_templates(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<StorageFile>>> {
    user.require(Permission::StorageRead)?;
    Ok(Json(
        state
            .services
            .library
            .list(StorageFileKind::CtTemplate)
            .await?,
    ))
}

async fn list_disk_images(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<StorageFile>>> {
    user.require(Permission::StorageRead)?;
    Ok(Json(
        state
            .services
            .library
            .list(StorageFileKind::DiskImage)
            .await?,
    ))
}

async fn upload_iso(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    body: Body,
) -> ApiResult<(StatusCode, Json<StorageFile>)> {
    user.require(Permission::StorageWrite)?;
    let file = state
        .services
        .library
        .upload(StorageFileKind::Iso, &name, body.into_data_stream())
        .await?;
    Ok((StatusCode::CREATED, Json(file)))
}

async fn upload_ct_template(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    body: Body,
) -> ApiResult<(StatusCode, Json<StorageFile>)> {
    user.require(Permission::StorageWrite)?;
    let file = state
        .services
        .library
        .upload(StorageFileKind::CtTemplate, &name, body.into_data_stream())
        .await?;
    Ok((StatusCode::CREATED, Json(file)))
}

async fn upload_disk_image(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
    body: Body,
) -> ApiResult<(StatusCode, Json<StorageFile>)> {
    user.require(Permission::StorageWrite)?;
    let file = state
        .services
        .library
        .upload(StorageFileKind::DiskImage, &name, body.into_data_stream())
        .await?;
    Ok((StatusCode::CREATED, Json(file)))
}

/// Import an uploaded disk image into a new ZFS zvol usable as a VM disk. The
/// image is resolved against the disk-image library (so only a genuinely
/// uploaded file can be imported) and converted into a freshly provisioned
/// zvol; the created dataset is returned for use as a VM disk's `dataset`.
async fn import_disk_image(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<ImportDiskImageRequest>,
) -> ApiResult<(StatusCode, Json<ImportDiskImageResponse>)> {
    user.require(Permission::StorageWrite)?;
    let source = state
        .services
        .library
        .resolve_disk_image(&req.image_name)
        .await?;
    let disk = state
        .services
        .kvm
        .import_disk_image(&source.to_string_lossy(), &req.dataset, req.size_gib)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(ImportDiskImageResponse {
            dataset: disk.dataset,
            size_gib: disk.size_gib,
        }),
    ))
}

async fn delete_iso(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::StorageWrite)?;
    state
        .services
        .library
        .delete(StorageFileKind::Iso, &name)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_ct_template(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::StorageWrite)?;
    state
        .services
        .library
        .delete(StorageFileKind::CtTemplate, &name)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_disk_image(
    user: AuthUser,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::StorageWrite)?;
    state
        .services
        .library
        .delete(StorageFileKind::DiskImage, &name)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
