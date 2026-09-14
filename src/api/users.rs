//! User-management endpoints (admin account CRUD).
//!
//! Account CRUD requires the `UserAdmin` permission. Changing one's *own*
//! password only requires being authenticated and lives with the other
//! `/auth/*` routes in [`crate::api::auth`].

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, patch};
use axum::{Json, Router};
use daygleve_schema::audit::AuditOutcome;
use daygleve_schema::auth::Permission;
use daygleve_schema::auth::{CreateUserRequest, UpdateUserRequest, User};

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::services::audit::NewAuditEvent;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/users", get(list).post(create))
        .route("/users/{id}", patch(update).delete(delete))
}

async fn list(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<Vec<User>>> {
    user.require(Permission::UserAdmin)?;
    Ok(Json(state.services.auth.list_users()))
}

async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> ApiResult<(StatusCode, Json<User>)> {
    user.require(Permission::UserAdmin)?;
    let created = state.services.auth.create_user(req).await?;
    state
        .services
        .audit
        .record(NewAuditEvent {
            actor_id: Some(user.0.user.id.clone()),
            actor: user.0.user.username.clone(),
            action: "user.create".to_string(),
            resource_type: Some("user".to_string()),
            resource_id: Some(created.id.clone()),
            outcome: AuditOutcome::Success,
            message: Some(format!("created user {:?}", created.username)),
            ..Default::default()
        })
        .await;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> ApiResult<Json<User>> {
    user.require(Permission::UserAdmin)?;
    let updated = state.services.auth.update_user(&id, req).await?;
    state
        .services
        .audit
        .record(NewAuditEvent {
            actor_id: Some(user.0.user.id.clone()),
            actor: user.0.user.username.clone(),
            action: "user.update".to_string(),
            resource_type: Some("user".to_string()),
            resource_id: Some(updated.id.clone()),
            outcome: AuditOutcome::Success,
            ..Default::default()
        })
        .await;
    Ok(Json(updated))
}

async fn delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::UserAdmin)?;
    state.services.auth.delete_user(&id).await?;
    state
        .services
        .audit
        .record(NewAuditEvent {
            actor_id: Some(user.0.user.id.clone()),
            actor: user.0.user.username.clone(),
            action: "user.delete".to_string(),
            resource_type: Some("user".to_string()),
            resource_id: Some(id.clone()),
            outcome: AuditOutcome::Success,
            ..Default::default()
        })
        .await;
    Ok(StatusCode::NO_CONTENT)
}
