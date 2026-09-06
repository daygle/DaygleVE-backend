//! Durable operation history and crash-recovery records.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::operations::{
    OperationRecord, QuarantineDecisionRequest, ReconcileRequest, ReconciliationQuarantineRecord,
};

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/operations", get(list))
        .route("/operations/reconcile", post(reconcile))
        .route("/operations/quarantine", get(list_quarantine))
        .route("/operations/quarantine/{id}", patch(decide_quarantine))
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
    body: Option<Json<ReconcileRequest>>,
) -> ApiResult<(StatusCode, Json<OperationRecord>)> {
    user.require(Permission::OperationsWrite)?;
    let request = body.map(|Json(value)| value).unwrap_or(ReconcileRequest {
        mode: daygleve_schema::operations::ReconciliationMode::DryRun,
        approval_id: None,
        quarantine_unmanaged: true,
    });
    let record = state
        .services
        .operations
        .enqueue_reconciliation(state.services.clone(), request)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(record)))
}

async fn list_quarantine(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<ReconciliationQuarantineRecord>>> {
    user.require(Permission::OperationsRead)?;
    Ok(Json(state.services.operations.list_quarantine().await?))
}

async fn decide_quarantine(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<QuarantineDecisionRequest>,
) -> ApiResult<Json<ReconciliationQuarantineRecord>> {
    user.require(Permission::OperationsWrite)?;
    let record = state
        .services
        .operations
        .decide_quarantine(
            &state.services,
            &id,
            body.decision,
            &user.0.user.id,
            body.message.as_deref(),
        )
        .await?;
    Ok(Json(record))
}
