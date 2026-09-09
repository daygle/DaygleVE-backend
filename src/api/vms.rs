//! Virtual-machine endpoints. Each handler authorizes via [`AuthUser::require`]
//! before delegating to the KVM service. The console websocket is the one
//! exception: it is authorized by a one-time ticket (minted by `POST
//! …/console`) rather than a bearer header, so a browser noVNC client can
//! attach directly.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use daygleve_schema::auth::Permission;
use daygleve_schema::operations::OperationRecord;
use daygleve_schema::pci::PciAssignment;
use daygleve_schema::usb::UsbAssignment;
use daygleve_schema::vm::{
    AttachVmPciRequest, AttachVmUsbRequest, CloneVmRequest, ConsoleTicket, CreateVmRequest,
    CreateVmSnapshotRequest, GuestAgentInfo, IsoImage, MigrateVmDiskRequest, ResizeVmDiskRequest,
    UpdateVmRequest, Vm, VmDisk, VmPowerRequest, VmPowerResponse, VmSnapshot, VmSummary,
};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::auth::AuthUser;
use crate::error::{ApiResult, AppError};
use crate::services::kvm::ConsoleTarget;
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/vms", get(list).post(create))
        .route("/vms/iso-images", get(iso_images))
        .route("/vms/{id}", get(get_one).patch(update).delete(delete))
        .route("/vms/{id}/power", post(power))
        .route("/vms/{id}/clone", post(clone_vm))
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
        .route(
            "/vms/{id}/snapshots/{name}/restore",
            post(restore_ram_snapshot),
        )
        .route("/vms/{id}/guest-agent", get(guest_agent))
        .route("/vms/{id}/disks/{index}/resize", post(resize_disk))
        .route("/vms/{id}/disks/migrate", post(migrate_disk))
        .route("/vms/{id}/disks", get(list_disks).post(attach_disk))
        .route(
            "/vms/{id}/disks/{index}",
            axum::routing::delete(detach_disk),
        )
        .route(
            "/vms/{id}/usb-devices",
            get(list_usb).post(attach_usb).delete(detach_usb),
        )
        .route(
            "/vms/{id}/pci-devices",
            get(list_pci).post(attach_pci).delete(detach_pci),
        )
        .route("/vms/{id}/console", post(console))
        .route("/vms/{id}/console/ws", get(console_ws))
        .route("/vms/{id}/serial-console", post(serial_console))
        .route("/vms/{id}/serial-console/ws", get(serial_console_ws))
        .route("/vms/{id}/spice", post(spice_connection))
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
) -> ApiResult<(StatusCode, Json<OperationRecord>)> {
    user.require(Permission::VmWrite)?;
    super::pools::ensure_pool_assignment(&state, &req.pool).await?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let actor = user.0.user.id.clone();
    let record = operations
        .enqueue(
            "vm.create",
            Some("vm"),
            None,
            Some(&actor),
            move |ops, handle| async move {
                ops.update_progress(&handle.id, 10, Some("provisioning disk"))
                    .await?;
                let vm = services.kvm.create(req).await?;
                ops.set_result_id(&handle.id, &vm.id).await?;
                Ok(Some(format!("created VM {}", vm.name)))
            },
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(record)))
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
    super::pools::ensure_pool_assignment(&state, &req.pool).await?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let vm = operations
        .run(
            "vm.update",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.kvm.update(&id, req).await },
        )
        .await?;
    Ok(Json(vm))
}

async fn delete(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    user.require(Permission::VmWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    operations
        .run(
            "vm.delete",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.kvm.delete(&id).await },
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn power(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<VmPowerRequest>,
) -> ApiResult<(StatusCode, Json<VmPowerResponse>)> {
    user.require(Permission::VmPower)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let response = operations
        .run(
            "vm.power",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.kvm.power(&id, req.action).await },
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(response)))
}

/// Guest-agent status and reported guest info (IPs, OS) for a running VM.
async fn guest_agent(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<GuestAgentInfo>> {
    user.require(Permission::VmRead)?;
    Ok(Json(state.services.kvm.guest_agent_info(&id).await?))
}

/// Restore a RAM-state snapshot: resume the VM from its saved memory image.
async fn restore_ram_snapshot(
    user: AuthUser,
    State(state): State<AppState>,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<Json<Vm>> {
    user.require(Permission::VmPower)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let vm = operations
        .run(
            "vm.restore_ram_snapshot",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move || async move {
                operation_services
                    .kvm
                    .restore_ram_snapshot(&id, &name)
                    .await
            },
        )
        .await?;
    Ok(Json(vm))
}

/// The VM's disks (a focused view of the same data the detail endpoint has).
async fn list_disks(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<VmDisk>>> {
    user.require(Permission::VmRead)?;
    let vm = state.services.kvm.get(&id).await?;
    Ok(Json(vm.disks))
}

/// Grow a disk's backing zvol (and notify the running guest).
async fn resize_disk(
    user: AuthUser,
    State(state): State<AppState>,
    Path((id, index)): Path<(String, usize)>,
    Json(req): Json<ResizeVmDiskRequest>,
) -> ApiResult<Json<Vm>> {
    user.require(Permission::VmWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let vm = operations
        .run(
            "vm.resize_disk",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.kvm.resize_disk(&id, index, req).await },
        )
        .await?;
    Ok(Json(vm))
}

/// Hot-attach an additional disk.
async fn attach_disk(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(disk): Json<VmDisk>,
) -> ApiResult<(StatusCode, Json<Vm>)> {
    user.require(Permission::VmWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let vm = operations
        .run(
            "vm.attach_disk",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.kvm.attach_disk(&id, disk).await },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(vm)))
}

/// Move one of the VM's disks to another ZFS dataset/pool (offline).
async fn migrate_disk(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<MigrateVmDiskRequest>,
) -> ApiResult<(StatusCode, Json<OperationRecord>)> {
    user.require(Permission::VmWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let record = operations
        .enqueue(
            "vm.migrate_disk",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move |ops, handle| async move {
                let disk_index = req.disk_index;
                ops.update_progress(&handle.id, 10, Some("migrating disk"))
                    .await?;
                let vm = services.kvm.migrate_disk(&id, req).await?;
                let new_dataset = vm
                    .disks
                    .get(disk_index)
                    .map(|d| d.dataset.clone())
                    .unwrap_or_default();
                Ok(Some(format!("migrated disk to {new_dataset}")))
            },
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(record)))
}

/// Detach a disk by index (its zvol and data are kept).
async fn detach_disk(
    user: AuthUser,
    State(state): State<AppState>,
    Path((id, index)): Path<(String, usize)>,
) -> ApiResult<Json<Vm>> {
    user.require(Permission::VmWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let vm = operations
        .run(
            "vm.detach_disk",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.kvm.detach_disk(&id, index).await },
        )
        .await?;
    Ok(Json(vm))
}

/// The VM's USB passthrough assignments (a focused view of the detail data).
async fn list_usb(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<UsbAssignment>>> {
    user.require(Permission::VmRead)?;
    let vm = state.services.kvm.get(&id).await?;
    Ok(Json(vm.usb_devices))
}

/// Hot-attach a host USB device (matched by vendor:product) to the VM.
async fn attach_usb(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<AttachVmUsbRequest>,
) -> ApiResult<(StatusCode, Json<Vm>)> {
    user.require(Permission::VmWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let vm = operations
        .run(
            "vm.attach_usb",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.kvm.attach_usb(&id, req).await },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(vm)))
}

/// Query parameters for USB detach: the vendor:product id to remove.
#[derive(Debug, Deserialize)]
struct DetachUsbQuery {
    vendor_id: String,
    product_id: String,
}

/// Detach a USB passthrough device from the VM (the device stays on the host).
async fn detach_usb(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<DetachUsbQuery>,
) -> ApiResult<Json<Vm>> {
    user.require(Permission::VmWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let vm = operations
        .run(
            "vm.detach_usb",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move || async move {
                operation_services
                    .kvm
                    .detach_usb(&id, &q.vendor_id, &q.product_id)
                    .await
            },
        )
        .await?;
    Ok(Json(vm))
}

/// The VM's PCI passthrough assignments (a focused view of the detail data).
async fn list_pci(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<PciAssignment>>> {
    user.require(Permission::VmRead)?;
    let vm = state.services.kvm.get(&id).await?;
    Ok(Json(vm.pci_devices))
}

/// Hot-attach a host PCI function to the VM.
async fn attach_pci(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<AttachVmPciRequest>,
) -> ApiResult<(StatusCode, HeaderMap, Json<Vm>)> {
    user.require(Permission::VmWrite)?;
    // Warn before invoking virsh when another guest already owns a function in
    // this device's IOMMU group. The operation remains allowed, but the warning
    // is exposed to cross-origin frontends through the standard `Warning` header.
    let iommu_warning = state
        .services
        .kvm
        .pci_iommu_group_warning(&id, &req.pci_address)
        .await?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let vm = operations
        .run(
            "vm.attach_pci",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.kvm.attach_pci(&id, req).await },
        )
        .await?;
    let mut headers = HeaderMap::new();
    if let Some(warning) = iommu_warning {
        let warning = format!("299 - \"{warning}\"");
        if let Ok(value) = HeaderValue::from_str(&warning) {
            headers.insert("warning", value);
        }
    }
    Ok((StatusCode::CREATED, headers, Json(vm)))
}

/// Query parameters for PCI detach: the device address to remove.
#[derive(Debug, Deserialize)]
struct DetachPciQuery {
    pci_address: String,
}

/// Detach a PCI passthrough device from the VM.
async fn detach_pci(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<DetachPciQuery>,
) -> ApiResult<Json<Vm>> {
    user.require(Permission::VmWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let vm = operations
        .run(
            "vm.detach_pci",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.kvm.detach_pci(&id, &q.pci_address).await },
        )
        .await?;
    Ok(Json(vm))
}

async fn clone_vm(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CloneVmRequest>,
) -> ApiResult<(StatusCode, Json<OperationRecord>)> {
    user.require(Permission::VmWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let record = operations
        .enqueue(
            "vm.clone",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move |ops, handle| async move {
                ops.update_progress(&handle.id, 10, Some("cloning disks"))
                    .await?;
                let vm = services.kvm.clone(&id, req).await?;
                ops.set_result_id(&handle.id, &vm.id).await?;
                Ok(Some(format!("cloned VM {}", vm.name)))
            },
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(record)))
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
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    let snap = operations
        .run(
            "vm.create_snapshot",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.kvm.create_snapshot(&id, req).await },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(snap)))
}

async fn rollback_snapshot(
    user: AuthUser,
    State(state): State<AppState>,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    user.require(Permission::VmWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    operations
        .run(
            "vm.rollback_snapshot",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.kvm.rollback_snapshot(&id, &name).await },
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_snapshot(
    user: AuthUser,
    State(state): State<AppState>,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    user.require(Permission::VmWrite)?;
    let services = state.services.clone();
    let operations = services.operations.clone();
    let operation_services = services.clone();
    let resource_id = id.clone();
    let actor = user.0.user.id.clone();
    operations
        .run(
            "vm.delete_snapshot",
            Some("vm"),
            Some(&resource_id),
            Some(&actor),
            move || async move { operation_services.kvm.delete_snapshot(&id, &name).await },
        )
        .await?;
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

/// Mint a one-time ticket for the VM's serial (text) console.
async fn serial_console(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<ConsoleTicket>> {
    user.require(Permission::VmPower)?;
    Ok(Json(state.services.kvm.serial_console(&id).await?))
}

/// Download a `remote-viewer` connection file (`.vv`) for the VM's SPICE
/// display. The client opens the returned file with `remote-viewer`.
async fn spice_connection(
    user: AuthUser,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    user.require(Permission::VmPower)?;
    let body = state.services.kvm.spice_connection(&id).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-virt-viewer"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"console.vv\"",
            ),
        ],
        body,
    )
        .into_response())
}

/// Query string for a console websocket: the one-time ticket.
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
        Ok(ConsoleTarget::Vnc(addr)) => ws.on_upgrade(move |socket| proxy_vnc(socket, addr)),
        Ok(ConsoleTarget::Serial(_)) => {
            AppError::validation("this ticket is for the serial console").into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Websocket endpoint the browser xterm.js client connects to for the serial
/// console. Authorized by the one-time `ticket`; on success it bridges the
/// domain's console pty (opened through the broker) to the socket.
async fn serial_console_ws(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<ConsoleQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    let pty = match state.services.kvm.redeem_ticket(&id, &q.ticket) {
        Ok(ConsoleTarget::Serial(pty)) => pty,
        Ok(ConsoleTarget::Vnc(_)) => {
            return AppError::validation("this ticket is for the graphical console").into_response()
        }
        Err(e) => return e.into_response(),
    };
    ws.on_upgrade(move |socket| async move {
        match state.services.kvm.attach_serial_console(&pty).await {
            Ok((reader, writer)) => proxy_console(socket, reader, writer).await,
            Err(_) => {
                let mut socket = socket;
                let _ = socket.send(Message::Close(None)).await;
            }
        }
    })
}

/// Bidirectionally bridge a websocket and a console byte-stream: browser
/// keystrokes -> console, console output -> browser binary frames. Shared by the
/// VM serial console and the LXC container console.
pub(crate) async fn proxy_console(
    socket: WebSocket,
    mut reader: crate::services::command::ConsoleReadHalf,
    mut writer: crate::services::command::ConsoleWriteHalf,
) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    let ws_to_console = async {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Binary(data) => {
                    if writer.send(data.as_ref()).await.is_err() {
                        break;
                    }
                }
                Message::Text(text) => {
                    if writer.send(text.as_bytes()).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    };

    let console_to_ws = async {
        while let Some(chunk) = reader.recv().await {
            if ws_tx.send(Message::Binary(chunk.into())).await.is_err() {
                break;
            }
        }
        let _ = ws_tx.close().await;
    };

    tokio::select! {
        _ = ws_to_console => {},
        _ = console_to_ws => {},
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
