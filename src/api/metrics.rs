//! Metrics endpoints: a point-in-time node snapshot and a real-time SSE stream.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::get;
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::metrics::{MetricsEvent, MetricsScope, NodeMetrics};
use futures::stream::Stream;
use tokio_stream::wrappers::IntervalStream;
use tokio_stream::StreamExt;

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

/// How often the SSE stream emits a node metrics frame.
const STREAM_INTERVAL: Duration = Duration::from_secs(2);

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/metrics/node", get(node))
        .route("/metrics/stream", get(stream))
}

async fn node(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<NodeMetrics>> {
    user.require(Permission::MetricsRead)?;
    Ok(Json(state.services.metrics.node().await))
}

/// `text/event-stream` of [`MetricsEvent`] frames. The frontend consumes this
/// for live dashboards. TODO(metrics): also fan out per-guest frames.
async fn stream(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    user.require(Permission::MetricsRead)?;

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
