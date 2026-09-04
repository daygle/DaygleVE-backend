//! Durable operation history and crash-recovery records.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::operations::OperationRecord;

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/operations", get(list))
        .route("/operations/reconcile", post(reconcile))
        .route("/operations/{id}", get(get_one))
}

async fn list(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<OperationRecord>>> {
    user.require(Permission::OperationsRead)?;
    Ok(Json(state.services.operations.list().await?))
}

async fn get_one(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<OperationRecord>> {
    user.require(Permission::OperationsRead)?;
    Ok(Json(state.services.operations.get(&id).await?))
}

async fn reconcile(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<(StatusCode, Json<OperationRecord>)> {
    user.require(Permission::OperationsWrite)?;
    let record = state
        .services
        .operations
        .enqueue_reconciliation(state.services.clone())
        .await?;
    Ok((StatusCode::ACCEPTED, Json(record)))
}
