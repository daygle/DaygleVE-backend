//! Virtual-machine endpoints. Each handler authorizes via [`AuthUser::require`]
//! before delegating to the KVM service. The console websocket is the one
//! exception: it is authorized by a one-time ticket (minted by `POST
//! …/console`) rather than a bearer header, so a browser noVNC client can
//! attach directly.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::vm::{
    ConsoleTicket, CreateVmRequest, CreateVmSnapshotRequest, IsoImage, UpdateVmRequest, Vm,
    VmPowerRequest, VmSnapshot, VmSummary,
};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/vms", get(list).post(create))
        .route("/vms/iso-images", get(iso_images))
        .route("/vms/{id}", get(get_one).patch(update).delete(delete))
        .route("/vms/{id}/power", post(power))
        .route(
            "/vms/{id}/snapshots",
            get(list_snapshots).post(create_snapshot),
        )
        .route(
            "/vms/{id}/snapshots/{name}",
            axum::routing::delete(delete_snapshot),
        )
        .route(
            "/vms/{id}/snapshots/{name}/rollback",
            post(rollback_snapshot),
        )
        .route("/vms/{id}/console", post(console))
        .route("/vms/{id}/console/ws", get(console_ws))
}

async fn list(user: AuthUser, State(state): State<AppState>) -> ApiResult<Json<Vec<VmSummary>>> {
    user.require(Permission::VmRead)?;
    Ok(Json(state.services.kvm.list().await?))
}

/// Installer/live ISOs available to attach as VM install media.
async fn iso_images(
    user: AuthUser,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<IsoImage>>> {
    user.require(Permission::VmRead)?;
    Ok(Json(state.services.kvm.list_isos().await?))
}

async fn create(
    user: AuthUser,
    State(state): State<AppState>,
    Json(req): Json<CreateVmRequest>,
) -> ApiResult<(StatusCode, Json<Vm>)> {
    user.require(Permission::VmWrite)?;
    let vm = state.services.kvm.create(req).await?;
    Ok((StatusCode::CREATED, Json(vm)))
}

async fn get_one(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Vm>> {
    user.require(Permission::VmRead)?;
    Ok(Json(state.services.kvm.get(&id).await?))
}

async fn update(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateVmRequest>,
) -> ApiResult<Json<Vm>> {
    user.require(Permission::VmWrite)?;
    Ok(Json(state.services.kvm.update(&id, req).await?))
}

async fn delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::VmWrite)?;
    state.services.kvm.delete(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn power(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<VmPowerRequest>,
) -> ApiResult<(StatusCode, Json<Vm>)> {
    user.require(Permission::VmPower)?;
    let vm = state.services.kvm.power(&id, req.action).await?;
    Ok((StatusCode::ACCEPTED, Json(vm)))
}

async fn list_snapshots(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<VmSnapshot>>> {
    user.require(Permission::VmRead)?;
    Ok(Json(state.services.kvm.list_snapshots(&id).await?))
}

async fn create_snapshot(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateVmSnapshotRequest>,
) -> ApiResult<(StatusCode, Json<VmSnapshot>)> {
    user.require(Permission::VmWrite)?;
    let snap = state.services.kvm.create_snapshot(&id, req).await?;
    Ok((StatusCode::CREATED, Json(snap)))
}

async fn rollback_snapshot(
    user: AuthUser,
    State(state): State<AppState>,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    user.require(Permission::VmWrite)?;
    state.services.kvm.rollback_snapshot(&id, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_snapshot(
    user: AuthUser,
    State(state): State<AppState>,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    user.require(Permission::VmWrite)?;
    state.services.kvm.delete_snapshot(&id, &name).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn console(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<ConsoleTicket>> {
    user.require(Permission::VmPower)?;
    Ok(Json(state.services.kvm.console(&id).await?))
}

/// Query string for the console websocket: the one-time ticket.
#[derive(Deserialize)]
struct ConsoleQuery {
    ticket: String,
}

/// Websocket endpoint the browser noVNC client connects to. Authorized by the
/// one-time `ticket` (not a bearer header); on success it proxies raw RFB bytes
/// between the socket and the domain's VNC port.
async fn console_ws(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<ConsoleQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    match state.services.kvm.redeem_ticket(&id, &q.ticket) {
        Ok(addr) => ws.on_upgrade(move |socket| proxy_vnc(socket, addr)),
        Err(e) => e.into_response(),
    }
}

/// Bidirectionally pipe a websocket and a raw VNC TCP socket (what websockify
/// does): browser RFB frames -> VNC, VNC bytes -> browser binary frames.
async fn proxy_vnc(socket: WebSocket, addr: String) {
    let tcp = match tokio::net::TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(_) => {
            // Close the browser socket cleanly instead of leaving it hanging.
            let mut socket = socket;
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
    };
    let (mut tcp_rd, mut tcp_wr) = tcp.into_split();
    let (mut ws_tx, mut ws_rx) = socket.split();

    let ws_to_tcp = async {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Binary(data) => {
                    if tcp_wr.write_all(data.as_ref()).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = tcp_wr.shutdown().await;
    };

    let tcp_to_ws = async {
        let mut buf = vec![0u8; 16384];
        loop {
            match tcp_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws_tx
                        .send(Message::Binary(buf[..n].to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = ws_tx.close().await;
    };

    tokio::select! {
        _ = ws_to_tcp => {},
        _ = tcp_to_ws => {},
    }
}
