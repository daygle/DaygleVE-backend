//! Metrics endpoints: a point-in-time node snapshot and a real-time SSE stream.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::metrics::{MetricsEvent, MetricsScope, NodeMetrics};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::IntervalStream;
use tokio_stream::StreamExt;

use crate::auth::AuthUser;
use crate::error::{ApiResult, AppError};
use crate::state::AppState;

/// How often the SSE stream emits a node metrics frame.
const STREAM_INTERVAL: Duration = Duration::from_secs(2);

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/metrics/node", get(node))
        .route("/metrics/stream/ticket", axum::routing::post(stream_ticket))
        .route("/metrics/stream", get(stream))
}

async fn node(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<NodeMetrics>> {
    user.require(Permission::MetricsRead)?;
    Ok(Json(state.services.metrics.node().await))
}

/// Short-lived, one-time authorization for opening the SSE metrics stream.
#[derive(Serialize)]
struct MetricsStreamTicket {
    ticket: String,
    expires_at: String,
}

/// Mint a stream ticket for an authenticated `MetricsRead` caller. The browser
/// exchanges its bearer token (sent here as a normal `Authorization` header) for
/// this ticket, then opens `EventSource` with `?ticket=…` — so the long-lived
/// token never travels in a URL (where it would land in history and proxy logs).
async fn stream_ticket(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<MetricsStreamTicket>> {
    user.require(Permission::MetricsRead)?;
    let (ticket, expires_at) = state.services.metrics.mint_stream_ticket(&user.0.user.id);
    Ok(Json(MetricsStreamTicket { ticket, expires_at }))
}

/// Query param carrying a one-time stream ticket for the SSE endpoint.
#[derive(Deserialize)]
struct StreamAuth {
    ticket: Option<String>,
}

/// `text/event-stream` of [`MetricsEvent`] frames. The frontend consumes this
/// for live dashboards. TODO(metrics): also fan out per-guest frames.
///
/// Authorized by a one-time `?ticket=` (minted via `POST /metrics/stream/ticket`)
/// because `EventSource` cannot set an `Authorization` header, or by a bearer
/// `Authorization` header for non-browser clients. A raw bearer token is
/// deliberately no longer accepted as a query param.
async fn stream(
    State(state): State<AppState>,
    Query(q): Query<StreamAuth>,
    headers: HeaderMap,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    // Preferred path: a one-time ticket, already bound to a MetricsRead caller
    // when it was minted.
    if let Some(ticket) = q.ticket {
        if state
            .services
            .metrics
            .redeem_stream_ticket(&ticket)
            .is_none()
        {
            return Err(AppError::unauthorized("invalid or expired stream ticket"));
        }
    } else {
        // Fallback for non-browser clients: a bearer token in the header (never
        // the URL), authorized inline.
        let token = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| AppError::unauthorized("missing stream ticket"))?;
        let user = state.services.auth.authenticate(token)?;
        if user.must_change_password {
            return Err(AppError::forbidden(
                "change the initial password before using the control plane",
            ));
        }
        if !user.permissions.contains(&Permission::MetricsRead) {
            return Err(AppError::forbidden("missing permission: MetricsRead"));
        }
    }

    let stream = IntervalStream::new(tokio::time::interval(STREAM_INTERVAL)).then(move |_| {
        let state = state.clone();
        async move {
            let frame = MetricsEvent {
                scope: MetricsScope::Node,
                node: Some(state.services.metrics.node().await),
                guest: None,
            };
            Ok(Event::default().json_data(frame).unwrap_or_default())
        }
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
