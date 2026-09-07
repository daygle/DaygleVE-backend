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
use daygleve_schema::storage_file::{StorageFile, StorageFileKind};

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
}

/// Large-body upload routes, mounted outside the global request-body limit.
pub fn upload_routes() -> Router<AppState> {
    Router::new()
        .route("/storage/isos/{name}", post(upload_iso))
        .route("/storage/ct-templates/{name}", post(upload_ct_template))
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
