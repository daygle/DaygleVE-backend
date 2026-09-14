//! Authentication endpoints: login, session identity, logout, and
//! self-service password change.
//!
//! `POST /auth/login` is additionally protected by per-IP and per-account
//! exponential backoff (see [`crate::services::login_throttle`]): each attempt
//! is delayed by the caller's accrued penalty before password verification, and
//! a still-active penalty beyond the delay cap is rejected with `429` and a
//! `retry-after` hint.

use std::net::IpAddr;

use axum::extract::ConnectInfo;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::audit::AuditOutcome;
use daygleve_schema::auth::{ChangePasswordRequest, CurrentUser, LoginRequest, LoginResponse};
use daygleve_schema::two_factor::{
    ConfirmTwoFactorRequest, DisableTwoFactorRequest, TwoFactorEnabledResponse,
    TwoFactorSetupResponse,
};
use tokio::time::sleep;

use crate::auth::AuthUser;
use crate::error::{ApiResult, AppError};
use crate::services::audit::NewAuditEvent;
use crate::state::AppState;

/// Penalties beyond this are rejected outright instead of sleeping, so a
/// heavily-penalized attacker cannot hold server tasks open indefinitely.
const MAX_ENFORCED_SLEEP: std::time::Duration = std::time::Duration::from_secs(10);

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/me", get(me))
        .route("/auth/logout", post(logout))
        .route("/auth/change-password", post(change_password))
        .route("/auth/2fa/setup", post(two_factor_setup))
        .route("/auth/2fa/confirm", post(two_factor_confirm))
        .route("/auth/2fa/disable", post(two_factor_disable))
}

async fn login(
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let ip = normalize_ip(peer.ip());

    // Serialize throttle decisions so concurrent attempts from one source
    // cannot all read the pre-penalty state. The delay itself is awaited
    // outside the lock: an attacker accrues wall-clock cost, not lock time.
    let (penalty, reject): (Option<std::time::Duration>, Option<std::time::Duration>) = {
        let mut throttle = state.login_throttle.lock().await;
        let penalty = throttle.penalty_for(ip, &req.username);
        if penalty > MAX_ENFORCED_SLEEP {
            let retry_after = throttle.record_failure(ip, &req.username);
            (None, Some(retry_after.max(penalty)))
        } else {
            (Some(penalty), None)
        }
    };

    if let Some(retry_after) = reject {
        return Err(too_many_attempts(retry_after));
    }

    // A deliberate small sleep even at zero penalty is NOT added: honest
    // logins should stay fast. The attacker's cost comes from penalties.
    if let Some(penalty) = penalty {
        if penalty > std::time::Duration::ZERO {
            sleep(penalty).await;
        }
    }
    let outcome = state.services.auth.login(req.clone()).await;
    let result = match outcome {
        // A correct password that merely needs a second factor is not a failed
        // attempt: return the challenge without touching the throttle or the
        // audit log, so a legitimate 2FA user is never penalized for the extra
        // round-trip and the log isn't spammed with benign "failures".
        Err(error) if error.is_two_factor_required() => return Err(error),
        Ok(response) => {
            state
                .login_throttle
                .lock()
                .await
                .record_success(ip, &req.username);
            state
                .services
                .audit
                .record(NewAuditEvent {
                    actor_id: Some(response.user.id.clone()),
                    actor: response.user.username.clone(),
                    action: "auth.login".to_string(),
                    outcome: AuditOutcome::Success,
                    source_ip: Some(ip.to_string()),
                    ..Default::default()
                })
                .await;
            Ok(Json(response))
        }
        Err(error) => {
            let retry_after = state
                .login_throttle
                .lock()
                .await
                .record_failure(ip, &req.username);
            state
                .services
                .audit
                .record(NewAuditEvent {
                    actor: req.username.clone(),
                    action: "auth.login".to_string(),
                    outcome: AuditOutcome::Failure,
                    message: Some("invalid credentials".to_string()),
                    source_ip: Some(ip.to_string()),
                    ..Default::default()
                })
                .await;
            if retry_after > MAX_ENFORCED_SLEEP {
                return Err(too_many_attempts(retry_after));
            }
            // Keep the standard 401 envelope so the error body never reveals
            // whether throttling is active vs. bad credentials.
            Err(error)
        }
    };
    result
}

/// Reject an attempt while a large penalty is still pending. `retry_after`
/// tells the client (and the log) when to come back.
fn too_many_attempts(retry_after: std::time::Duration) -> AppError {
    AppError::too_many_requests(format!(
        "too many failed login attempts; try again in {} seconds",
        retry_after.as_secs().max(1)
    ))
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    // IPv6-mapped IPv4 and loopback prefixes are folded to their IPv4 form so
    // per-IP buckets line up across dual-stack sockets.
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        other => other,
    }
}

async fn me(user: AuthUser) -> Json<CurrentUser> {
    Json(user.0)
}

async fn logout(user: AuthUser, State(state): State<AppState>) -> StatusCode {
    state.services.auth.logout(&user.1);
    state
        .services
        .audit
        .record(NewAuditEvent {
            actor_id: Some(user.0.user.id.clone()),
            actor: user.0.user.username.clone(),
            action: "auth.logout".to_string(),
            outcome: AuditOutcome::Success,
            ..Default::default()
        })
        .await;
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
    state
        .services
        .audit
        .record(NewAuditEvent {
            actor_id: Some(user.0.user.id.clone()),
            actor: user.0.user.username.clone(),
            action: "auth.change_password".to_string(),
            outcome: AuditOutcome::Success,
            ..Default::default()
        })
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Begin TOTP enrollment for the caller: returns a fresh shared secret and
/// provisioning URI. The second factor is not active until confirmed.
async fn two_factor_setup(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<TwoFactorSetupResponse>> {
    let response = state
        .services
        .auth
        .two_factor_setup(&user.0.user.id)
        .await?;
    Ok(Json(response))
}

/// Confirm TOTP enrollment with a code from the authenticator; on success the
/// second factor is enabled and one-time recovery codes are returned.
async fn two_factor_confirm(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<ConfirmTwoFactorRequest>,
) -> ApiResult<Json<TwoFactorEnabledResponse>> {
    let response = state
        .services
        .auth
        .two_factor_confirm(&user.0.user.id, &req.code)
        .await?;
    state
        .services
        .audit
        .record(NewAuditEvent {
            actor_id: Some(user.0.user.id.clone()),
            actor: user.0.user.username.clone(),
            action: "auth.2fa.enable".to_string(),
            outcome: AuditOutcome::Success,
            ..Default::default()
        })
        .await;
    Ok(Json(response))
}

/// Disable the caller's second factor after verifying a current code.
async fn two_factor_disable(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<DisableTwoFactorRequest>,
) -> ApiResult<StatusCode> {
    state
        .services
        .auth
        .two_factor_disable(&user.0.user.id, &req.code)
        .await?;
    state
        .services
        .audit
        .record(NewAuditEvent {
            actor_id: Some(user.0.user.id.clone()),
            actor: user.0.user.username.clone(),
            action: "auth.2fa.disable".to_string(),
            outcome: AuditOutcome::Success,
            ..Default::default()
        })
        .await;
    Ok(StatusCode::NO_CONTENT)
}
