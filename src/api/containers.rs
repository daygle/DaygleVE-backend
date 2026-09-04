//! LXC container endpoints.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::lxc::{CreateLxcRequest, Lxc, LxcPowerRequest, LxcSummary, UpdateLxcRequest};

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/containers", get(list).post(create))
        .route(
            "/containers/{id}",
            get(get_one).patch(update).delete(delete),
        )
        .route("/containers/{id}/power", post(power))
}

async fn list(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<Vec<LxcSummary>>> {
    user.require(Permission::LxcRead)?;
    Ok(Json(state.services.lxc.list().await?))
}

async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateLxcRequest>,
) -> ApiResult<(StatusCode, Json<Lxc>)> {
    user.require(Permission::LxcWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let ct = operations
        .run(
            "container.create",
            Some("container"),
            None,
            move || async move { operation_services.lxc.create(req).await },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(ct)))
}

async fn get_one(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Lxc>> {
    user.require(Permission::LxcRead)?;
    Ok(Json(state.services.lxc.get(&id).await?))
}

async fn update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateLxcRequest>,
) -> ApiResult<Json<Lxc>> {
    user.require(Permission::LxcWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let ct = operations
        .run(
            "container.update",
            Some("container"),
            Some(&resource_id),
            move || async move { operation_services.lxc.update(&id, req).await },
        )
        .await?;
    Ok(Json(ct))
}

async fn delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::LxcWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    operations
        .run(
            "container.delete",
            Some("container"),
            Some(&resource_id),
            move || async move { operation_services.lxc.delete(&id).await },
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn power(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<LxcPowerRequest>,
) -> ApiResult<(StatusCode, Json<Lxc>)> {
    user.require(Permission::LxcPower)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let ct = operations
        .run(
            "container.power",
            Some("container"),
            Some(&resource_id),
            move || async move { operation_services.lxc.power(&id, req.action).await },
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(ct)))
}
