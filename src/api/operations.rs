//! Durable operation history and crash-recovery records.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::operations::OperationRecord;

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/operations", get(list))
}

async fn list(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<OperationRecord>>> {
    user.require(Permission::OperationsRead)?;
    Ok(Json(state.services.operations.list().await?))
}
