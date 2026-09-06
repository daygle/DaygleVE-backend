//! Authentication endpoints: login, session identity, logout, and
//! self-service password change.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::auth::{ChangePasswordRequest, CurrentUser, LoginRequest, LoginResponse};

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/me", get(me))
        .route("/auth/logout", post(logout))
        .route("/auth/change-password", post(change_password))
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    Ok(Json(state.services.auth.login(req)?))
}

async fn me(user: AuthUser) -> Json<CurrentUser> {
    Json(user.0)
}

async fn logout(user: AuthUser, State(state): State<AppState>) -> StatusCode {
    state.services.auth.logout(&user.1);
    StatusCode::NO_CONTENT
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
        .change_password(&user.0.user.id, &user.1, req)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
