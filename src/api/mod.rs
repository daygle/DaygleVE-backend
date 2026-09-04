//! HTTP API layer: router assembly and the versioned route tree.
//!
//! All routes are mounted under `/api/{API_VERSION}` (currently `/api/v1`),
//! matching the OpenAPI document in DaygleVE-schema. Handlers are thin: they
//! authenticate, authorize, delegate to a service, and serialise schema types.

mod containers;
mod gpus;
mod health;
mod metrics;
mod network;
mod operations;
mod storage;
mod users;
mod vms;

pub mod auth;

use axum::body::Body;
use axum::http::{HeaderValue, Request};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use daygleve_schema::common::API_VERSION;
use http_body_util::BodyExt;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use crate::state::AppState;

/// Build the full application router.
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .merge(health::routes())
        .merge(auth::routes())
        .merge(users::routes())
        .merge(vms::routes())
        .merge(containers::routes())
        .merge(storage::routes())
        .merge(network::routes())
        .merge(operations::routes())
        .merge(gpus::routes())
        .merge(metrics::routes());

    let cors = cors_layer(&state.config.cors_origins);

    let mut app = Router::new().nest(&format!("/api/{API_VERSION}"), api);

    // On the appliance, serve the prebuilt frontend SPA for every non-API path,
    // falling back to index.html so client-side routing works. In dev
    // (`DAYGLEVE_WEB_ROOT` unset) this is skipped and the SvelteKit dev server
    // serves the UI on its own port.
    if let Some(web_root) = &state.config.web_root {
        let index = web_root.join("index.html");
        let serve = ServeDir::new(web_root).fallback(ServeFile::new(index));
        app = app.fallback_service(serve);
        tracing::info!(web_root = %web_root.display(), "serving frontend assets");
    }

    // Trace requests by method + path only. The path deliberately excludes the
    // query string so short-lived secrets passed there (e.g. the one-time VNC
    // console ticket on the console websocket) are never written to logs.
    let trace = TraceLayer::new_for_http().make_span_with(
        |req: &axum::http::Request<axum::body::Body>| {
            tracing::info_span!("http", method = %req.method(), path = %req.uri().path())
        },
    );

    app.layer(trace)
        .layer(cors)
        .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024))
        .layer(middleware::from_fn(request_id))
        .with_state(state)
}

/// Add a request correlation id to every response. The value is deliberately
/// generated at the HTTP boundary so even parse/auth failures are traceable.
async fn request_id(request: Request<Body>, next: Next) -> Response {
    let id = uuid::Uuid::new_v4().to_string();
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert("x-frame-options", HeaderValue::from_static("DENY"));
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));

    // Keep the response header and the standard JSON error envelope correlated,
    // including extractor/routing failures that never reach a handler.
    if response.status().is_client_error() || response.status().is_server_error() {
        let (parts, body) = response.into_parts();
        if let Ok(bytes) = body.collect().await.map(|b| b.to_bytes()) {
            if let Ok(mut error) =
                serde_json::from_slice::<daygleve_schema::common::ApiError>(&bytes)
            {
                error.request_id = Some(id);
                let body = serde_json::to_vec(&error).unwrap_or_else(|_| bytes.to_vec());
                let mut parts = parts;
                parts.headers.remove("content-length");
                return Response::from_parts(parts, Body::from(body));
            }
            return Response::from_parts(parts, Body::from(bytes));
        }
        return Response::from_parts(parts, Body::empty());
    }
    response
}

/// Build the CORS layer. An empty allow-list means same-origin only; production
/// deployments must explicitly configure the frontend origin(s).
fn cors_layer(origins: &[String]) -> CorsLayer {
    if origins.is_empty() {
        return CorsLayer::new();
    }
    let parsed: Vec<_> = origins
        .iter()
        .filter_map(|o| o.parse::<axum::http::HeaderValue>().ok())
        .collect();
    CorsLayer::new()
        .allow_origin(parsed)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any)
}
