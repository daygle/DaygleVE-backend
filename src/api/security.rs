//! Security posture endpoints: the current broker split inventory.
//!
//! This is a read-only, authenticated view of the residual root-equivalent
//! surface documented in the service layer. It exists so the "the broker split
//! is not finished yet" state is machine-checkable rather than prose-only.

use axum::extract::State;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use daygleve_schema::acme::{AcmeStatus, UpdateAcmeConfigRequest};
use daygleve_schema::audit::AuditOutcome;
use daygleve_schema::auth::Permission;
use daygleve_schema::broker::BrokerSplitInventory;

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::services::audit::NewAuditEvent;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/system/broker-split", get(broker_split))
        .route("/security/acme", get(acme_status))
        .route("/security/acme/config", put(update_acme_config))
        .route("/security/acme/issue", post(issue_acme))
}

/// Current ACME/TLS certificate configuration and status.
async fn acme_status(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<AcmeStatus>> {
    user.require(Permission::TlsRead)?;
    Ok(Json(state.services.acme.status().await))
}

/// Replace the ACME configuration. Returns the resulting status (issuance, if
/// warranted, is triggered separately via the issue endpoint or the renewal
/// scheduler).
async fn update_acme_config(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<UpdateAcmeConfigRequest>,
) -> ApiResult<Json<AcmeStatus>> {
    user.require(Permission::TlsWrite)?;
    state.services.acme.update_config(req).await?;
    state
        .services
        .audit
        .record(NewAuditEvent {
            actor_id: Some(user.0.user.id.clone()),
            actor: user.0.user.username.clone(),
            action: "acme.config.update".to_string(),
            resource_type: Some("acme".to_string()),
            outcome: AuditOutcome::Success,
            ..Default::default()
        })
        .await;
    Ok(Json(state.services.acme.status().await))
}

/// Trigger certificate issuance/renewal now, in the background. Returns the
/// status with `state` set to `pending` while issuance runs.
async fn issue_acme(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<AcmeStatus>> {
    user.require(Permission::TlsWrite)?;
    let status = state.services.acme.trigger_issue().await?;
    state
        .services
        .audit
        .record(NewAuditEvent {
            actor_id: Some(user.0.user.id.clone()),
            actor: user.0.user.username.clone(),
            action: "acme.issue".to_string(),
            resource_type: Some("acme".to_string()),
            outcome: AuditOutcome::Success,
            ..Default::default()
        })
        .await;
    Ok(Json(status))
}

async fn broker_split(user: AuthUser) -> ApiResult<Json<BrokerSplitInventory>> {
    user.require(Permission::OperationsRead)?;
    let broker_enabled: bool = {
        #[cfg(unix)]
        {
            match std::env::var_os("DAYGLEVE_BROKER_SOCKET")
                .filter(|path| !path.is_empty())
                .map(std::path::PathBuf::from)
            {
                Some(path) => crate::broker::client::BrokerClient::new(path)
                    .ping()
                    .await
                    .is_ok(),
                None => false,
            }
        }
        #[cfg(not(unix))]
        {
            false
        }
    };
    let inventory = if broker_enabled {
        let mut inventory = BrokerSplitInventory::current(crate::services::now_ts());
        inventory.current_execution = daygleve_schema::broker::HostExecution::Broker;
        inventory.broker_split_incomplete = false;
        inventory.note = Some(
            "Privileged host requests are configured to use the root-owned broker; real-host systemd/AppArmor validation remains required.".to_string(),
        );
        for subsystem in &mut inventory.subsystems {
            subsystem.mode = daygleve_schema::broker::BrokerMode::Delegated;
            subsystem.execution = daygleve_schema::broker::HostExecution::Broker;
            subsystem.current_actions.clear();
        }
        inventory
    } else {
        BrokerSplitInventory::current(crate::services::now_ts())
    };
    Ok(Json(inventory))
}
