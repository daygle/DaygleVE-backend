//! Metric-threshold alert-rule endpoints: CRUD over the rule set.
//!
//! Reading rules needs `NotificationRead`; creating, modifying, or deleting
//! needs `NotificationWrite` (the same trust level as notification channels -
//! a rule is just another thing that can page people). Evaluation happens on
//! the background metrics tick, not here.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::notification::{AlertRule, CreateAlertRuleRequest, UpdateAlertRuleRequest};

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/alerts", get(list).post(create))
        .route("/alerts/{id}", get(get_one).patch(update).delete(delete))
}

async fn list(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<Vec<AlertRule>>> {
    user.require(Permission::NotificationRead)?;
    Ok(Json(state.services.alerts.list().await?))
}

async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateAlertRuleRequest>,
) -> ApiResult<(StatusCode, Json<AlertRule>)> {
    user.require(Permission::NotificationWrite)?;
    let created = state.services.alerts.create(req).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

async fn get_one(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<AlertRule>> {
    user.require(Permission::NotificationRead)?;
    Ok(Json(state.services.alerts.get(&id).await?))
}

async fn update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateAlertRuleRequest>,
) -> ApiResult<Json<AlertRule>> {
    user.require(Permission::NotificationWrite)?;
    Ok(Json(state.services.alerts.update(&id, req).await?))
}

async fn delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::NotificationWrite)?;
    state.services.alerts.delete(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}
