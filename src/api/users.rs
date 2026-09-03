//! User-management and self-service password endpoints.
//!
//! Account CRUD requires the `UserAdmin` permission; changing one's *own*
//! password only requires being authenticated.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::auth::{ChangePasswordRequest, CreateUserRequest, UpdateUserRequest, User};

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/users", get(list).post(create))
        .route("/users/{id}", patch(update).delete(delete))
        .route("/auth/change-password", post(change_password))
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
    Ok((StatusCode::CREATED, Json(created)))
}

async fn update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> ApiResult<Json<User>> {
    user.require(Permission::UserAdmin)?;
    Ok(Json(state.services.auth.update_user(&id, req).await?))
}

async fn delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::UserAdmin)?;
    state.services.auth.delete_user(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Change the authenticated caller's own password.
async fn change_password(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<ChangePasswordRequest>,
) -> ApiResult<StatusCode> {
    state
        .services
        .auth
        .change_password(&user.0.user.id, req)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
