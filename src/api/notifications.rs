//! Notification-channel endpoints: CRUD plus a "send test" action.
//!
//! Reading channels needs `NotificationRead`; creating, modifying, deleting, or
//! testing needs `NotificationWrite`. Secrets are never returned - the channel
//! view only reports whether one is stored.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::notification::{
    CreateNotificationChannelRequest, NotificationChannel, UpdateNotificationChannelRequest,
};

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/notifications", get(list).post(create))
        .route(
            "/notifications/{id}",
            get(get_one).patch(update).delete(delete),
        )
        .route("/notifications/{id}/test", post(test))
}

async fn list(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<NotificationChannel>>> {
    user.require(Permission::NotificationRead)?;
    Ok(Json(state.services.notifications.list().await?))
}

async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateNotificationChannelRequest>,
) -> ApiResult<(StatusCode, Json<NotificationChannel>)> {
    user.require(Permission::NotificationWrite)?;
    let created = state.services.notifications.create(req).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_one(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<NotificationChannel>> {
    user.require(Permission::NotificationRead)?;
    Ok(Json(state.services.notifications.get(&id).await?))
}

async fn update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateNotificationChannelRequest>,
) -> ApiResult<Json<NotificationChannel>> {
    user.require(Permission::NotificationWrite)?;
    Ok(Json(state.services.notifications.update(&id, req).await?))
}

async fn delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::NotificationWrite)?;
    state.services.notifications.delete(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn test(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::NotificationWrite)?;
    state.services.notifications.send_test(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}
