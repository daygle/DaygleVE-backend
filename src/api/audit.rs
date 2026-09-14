//! Audit-log endpoint: a read-only, admin-gated view of recent security
//! events. Events are written internally by other handlers; there is
//! deliberately no endpoint to create or modify them.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use daygleve_schema::audit::AuditEvent;
use daygleve_schema::auth::Permission;
use serde::Deserialize;

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

/// Default and maximum number of events returned.
const DEFAULT_LIMIT: usize = 200;
const MAX_LIMIT: usize = 1000;

#[derive(Debug, Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/audit", get(list_audit))
}

async fn list_audit(
    user: AuthUser,
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditEvent>>> {
    user.require(Permission::AuditRead)?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    Ok(Json(state.services.audit.list(limit).await?))
}
