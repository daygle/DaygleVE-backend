//! LXC container endpoints.

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::lxc::{CreateLxcRequest, Lxc, LxcPowerRequest, LxcSummary, UpdateLxcRequest};
use daygleve_schema::lxc_snapshot::{CreateLxcSnapshotRequest, LxcSnapshot};
use daygleve_schema::operations::OperationRecord;
use daygleve_schema::vm::ConsoleTicket;
use serde::Deserialize;

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/containers", get(list).post(create))
        .route(
            "/containers/{id}",
            get(get_one).patch(update).delete(delete),
        )
        .route("/containers/{id}/power", post(power))
        .route(
            "/containers/{id}/snapshots",
            get(list_snapshots).post(create_snapshot),
        )
        .route(
            "/containers/{id}/snapshots/{name}",
            axum::routing::delete(delete_snapshot),
        )
        .route(
            "/containers/{id}/snapshots/{name}/rollback",
            post(rollback_snapshot),
        )
        .route("/containers/{id}/console", post(console))
        .route("/containers/{id}/console/ws", get(console_ws))
}

/// Mint a one-time ticket for the container's console.
async fn console(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<ConsoleTicket>> {
    user.require(Permission::LxcPower)?;
    Ok(Json(state.services.lxc.console(&id).await?))
}

/// Query string for the console websocket: the one-time ticket.
#[derive(Deserialize)]
struct ConsoleQuery {
    ticket: String,
}

/// Websocket endpoint the browser xterm.js client connects to for the container
/// console. Authorized by the one-time `ticket`; on success it bridges the
/// container's console (opened through the broker) to the socket.
async fn console_ws(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<ConsoleQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let name = match state.services.lxc.redeem_console_ticket(&id, &q.ticket) {
        Ok(name) => name,
        Err(e) => return e.into_response(),
    };
    ws.on_upgrade(move |socket| async move {
        match state.services.lxc.attach_console(&name).await {
            Ok((reader, writer)) => super::vms::proxy_console(socket, reader, writer).await,
            Err(_) => {
                use axum::extract::ws::Message;
                let mut socket = socket;
                let _ = socket.send(Message::Close(None)).await;
            }
        }
    })
}

async fn list(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<Vec<LxcSummary>>> {
    user.require(Permission::LxcRead)?;
    Ok(Json(state.services.lxc.list().await?))
}

async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateLxcRequest>,
) -> ApiResult<(StatusCode, Json<OperationRecord>)> {
    user.require(Permission::LxcWrite)?;
    super::pools::ensure_pool_assignment(&state, &req.pool).await?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let actor = user.0.user.id.clone();
    let record = operations
        .enqueue(
            "container.create",
            Some("container"),
            None,
            Some(&actor),
            move |ops, handle| async move {
                ops.update_progress(&handle.id, 10, Some("downloading template"))
                    .await?;
                let ct = services.lxc.create(req).await?;
                ops.set_result_id(&handle.id, &ct.id).await?;
                Ok(Some(format!("created container {}", ct.name)))
            },
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(record)))
}

async fn get_one(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Lxc>> {
    user.require(Permission::LxcRead)?;
    Ok(Json(state.services.lxc.get(&id).await?))
}

async fn update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateLxcRequest>,
) -> ApiResult<Json<Lxc>> {
    user.require(Permission::LxcWrite)?;
    super::pools::ensure_pool_assignment(&state, &req.pool).await?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let ct = operations
        .run(
            "container.update",
            Some("container"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.lxc.update(&id, req).await },
        )
        .await?;
    Ok(Json(ct))
}

async fn delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::LxcWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    operations
        .run(
            "container.delete",
            Some("container"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.lxc.delete(&id).await },
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_snapshots(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<LxcSnapshot>>> {
    user.require(Permission::LxcRead)?;
    Ok(Json(state.services.lxc.list_snapshots(&id).await?))
}

async fn create_snapshot(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateLxcSnapshotRequest>,
) -> ApiResult<(StatusCode, Json<LxcSnapshot>)> {
    user.require(Permission::LxcWrite)?;
    let snapshot = state
        .services
        .lxc
        .snapshot(&id, &req.name, req.description.as_deref())
        .await?;
    Ok((StatusCode::CREATED, Json(snapshot)))
}

async fn rollback_snapshot(
    user: AuthUser,
    State(state): State<AppState>,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    user.require(Permission::LxcWrite)?;
    state.services.lxc.rollback_snapshot(&id, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_snapshot(
    user: AuthUser,
    State(state): State<AppState>,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    user.require(Permission::LxcWrite)?;
    state.services.lxc.delete_snapshot(&id, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn power(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<LxcPowerRequest>,
) -> ApiResult<(StatusCode, Json<Lxc>)> {
    user.require(Permission::LxcPower)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let ct = operations
        .run(
            "container.power",
            Some("container"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.lxc.power(&id, req.action).await },
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(ct)))
}
