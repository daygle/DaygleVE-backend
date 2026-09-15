//! Access-control (ACL) endpoints: list, grant, and revoke path-scoped role
//! assignments. Managing the ACL is itself an administrative action, gated on
//! `UserAdmin` at the node root.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use daygleve_schema::audit::AuditOutcome;
use daygleve_schema::auth::Permission;
use daygleve_schema::rbac::{AclEntry, CreateAclEntryRequest};

use crate::auth::AuthUser;
use crate::error::{ApiResult, AppError};
use crate::services::audit::NewAuditEvent;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/acl", get(list_acl).post(create_acl))
        .route("/acl/{id}", axum::routing::delete(delete_acl))
}

/// All ACL entries, ordered by path.
async fn list_acl(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<Vec<AclEntry>>> {
    user.require(Permission::UserAdmin)?;
    Ok(Json(state.services.acl.list()))
}

/// Grant a role on a path to a user.
async fn create_acl(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateAclEntryRequest>,
) -> ApiResult<(StatusCode, Json<AclEntry>)> {
    user.require(Permission::UserAdmin)?;
    // The subject must be a real account; capture its username for display.
    let subject = state
        .services
        .auth
        .user_by_id(&req.subject)
        .ok_or_else(|| AppError::validation("subject user does not exist"))?;
    let propagate = req.propagate.unwrap_or(true);
    let entry = state
        .services
        .acl
        .create(
            &req.path,
            &subject.id,
            &subject.username,
            req.role,
            propagate,
        )
        .await?;
    state
        .services
        .audit
        .record(NewAuditEvent {
            actor_id: Some(user.0.user.id.clone()),
            actor: user.0.user.username.clone(),
            action: "acl.grant".to_string(),
            resource_type: Some("acl".to_string()),
            resource_id: Some(entry.id.clone()),
            outcome: AuditOutcome::Success,
            message: Some(format!(
                "{:?} to {} on {}",
                entry.role, subject.username, entry.path
            )),
            ..Default::default()
        })
        .await;
    Ok((StatusCode::CREATED, Json(entry)))
}

/// Revoke one ACL entry.
async fn delete_acl(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::UserAdmin)?;
    state.services.acl.delete(&id).await?;
    state
        .services
        .audit
        .record(NewAuditEvent {
            actor_id: Some(user.0.user.id.clone()),
            actor: user.0.user.username.clone(),
            action: "acl.revoke".to_string(),
            resource_type: Some("acl".to_string()),
            resource_id: Some(id),
            outcome: AuditOutcome::Success,
            ..Default::default()
        })
        .await;
    Ok(StatusCode::NO_CONTENT)
}
