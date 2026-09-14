//! API token endpoints: a caller manages their own long-lived access tokens.
//!
//! Any authenticated user may mint tokens scoped to a subset of their own
//! permissions, list them, and revoke them. The raw secret is returned only
//! from the create endpoint, once.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{delete, get};
use axum::{Json, Router};
use daygleve_schema::api_token::{ApiToken, CreateApiTokenRequest, CreateApiTokenResponse};
use daygleve_schema::audit::AuditOutcome;

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::services::audit::NewAuditEvent;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/tokens", get(list_tokens).post(create_token))
        .route("/tokens/{id}", delete(delete_token))
}

async fn list_tokens(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<ApiToken>>> {
    Ok(Json(
        state.services.api_tokens.list_for(&user.0.user.id).await?,
    ))
}

async fn create_token(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateApiTokenRequest>,
) -> ApiResult<(StatusCode, Json<CreateApiTokenResponse>)> {
    let (token, api_token) = state
        .services
        .api_tokens
        .create(
            &user.0.user.id,
            &user.0.user.username,
            &user.0.permissions,
            req,
        )
        .await?;
    state
        .services
        .audit
        .record(NewAuditEvent {
            actor_id: Some(user.0.user.id.clone()),
            actor: user.0.user.username.clone(),
            action: "api_token.create".to_string(),
            resource_type: Some("api_token".to_string()),
            resource_id: Some(api_token.id.clone()),
            outcome: AuditOutcome::Success,
            message: Some(format!("created token {:?}", api_token.name)),
            ..Default::default()
        })
        .await;
    Ok((
        StatusCode::CREATED,
        Json(CreateApiTokenResponse { token, api_token }),
    ))
}

async fn delete_token(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    state
        .services
        .api_tokens
        .delete(&user.0.user.id, &id)
        .await?;
    state
        .services
        .audit
        .record(NewAuditEvent {
            actor_id: Some(user.0.user.id.clone()),
            actor: user.0.user.username.clone(),
            action: "api_token.revoke".to_string(),
            resource_type: Some("api_token".to_string()),
            resource_id: Some(id.clone()),
            outcome: AuditOutcome::Success,
            ..Default::default()
        })
        .await;
    Ok(StatusCode::NO_CONTENT)
}
