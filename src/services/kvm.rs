//! KVM/QEMU virtual-machine lifecycle service.
//!
//! Drives libvirt via `virsh` (connected to `qemu:///system`). libvirt persists
//! the domain itself; DaygleVE keeps a sidecar JSON record of the structured
//! `Vm` (disks, NICs, firmware, description) that libvirt XML does not
//! round-trip cleanly, and always overlays the *live* power state from
//! `virsh domstate` at read time. Disks are backed by ZFS zvols
//! (`/dev/zvol/<dataset>`), provisioned on create.
//!
//! The console endpoint mints a short-lived one-time ticket bound to the
//! domain's VNC socket; the websocket proxy in [`crate::api::vms`] validates the
//! ticket and pipes raw RFB bytes so a browser noVNC client can attach.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use daygleve_schema::vm::{
    ConsoleTicket, CreateVmRequest, CreateVmSnapshotRequest, DiskBus, Firmware, IsoImage, NicModel,
    UpdateVmRequest, Vm, VmDisk, VmNic, VmPowerAction, VmSnapshot, VmState, VmSummary,
};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::shares::ShareService;
use crate::services::store::JsonStore;
use crate::services::{command, new_id, now_ts};

/// How long a console ticket is valid before the client must re-request one.
const TICKET_TTL: Duration = Duration::from_secs(60);

/// How many directory levels deep to search a network share for ISOs. Deep
/// enough for the common `iso/` or `template/iso/` layouts without walking an
/// arbitrarily large tree.
const ISO_SCAN_DEPTH: u32 = 4;

/// A pending console ticket bound to a domain's VNC socket.
struct Ticket {
    vm_id: String,
    vnc_addr: String,
    expires_at: Instant,
}

pub struct KvmService {
    store: JsonStore,
    config: Arc<Config>,
    shares: Arc<ShareService>,
    tickets: RwLock<HashMap<String, Ticket>>,
}

impl KvmService {
    pub fn new(config: Arc<Config>, shares: Arc<ShareService>) -> Self {
        Self {
            store: JsonStore::new(&config.state_dir, "vms"),
            config,
            shares,
            tickets: RwLock::new(HashMap::new()),
        }
    }

    pub async fn list(&self) -> ApiResult<Vec<VmSummary>> {
        let vms: Vec<Vm> = self.store.list().await?;
        let mut out = Vec::with_capacity(vms.len());
        for mut vm in vms {
            vm.state = self.live_state(&vm.id).await.unwrap_or(vm.state);
            out.push(summary_of(&vm));
        }
        Ok(out)
    }

    pub async fn get(&self, id: &str) -> ApiResult<Vm> {
        let mut vm = self.get_stored(id).await?;
        vm.state = self.live_state(&vm.id).await.unwrap_or(vm.state);
        Ok(vm)
    }

    pub async fn create(&self, req: CreateVmRequest) -> ApiResult<Vm> {
        if req.name.trim().is_empty() {
            return Err(AppError::validation("name must not be empty"));
        }
        // The name becomes the libvirt domain name; keep it path/shell-safe.
        crate::services::ensure_safe_id(&req.name)?;
        if req.vcpus == 0 {
            return Err(AppError::validation("vcpus must be >= 1"));
        }
        if req.memory_mib == 0 {
            return Err(AppError::validation("memory_mib must be >= 1"));
        }

        // Validate any requested install ISO against the node's library before
        // it reaches libvirt (prevents pointing a VM at an arbitrary host file).
        let cdrom = match req.cdrom {
            Some(path) => Some(self.resolve_iso(&path).await?),
            None => None,
        };

        // Provision a zvol for each disk that names a size (best-effort: an
        // existing dataset is reused).
        for disk in &req.disks {
            self.ensure_zvol(disk).await?;
        }

        let vm = Vm {
            id: new_id(),
            name: req.name,
            state: VmState::Stopped,
            vcpus: req.vcpus,
            memory_mib: req.memory_mib,
            firmware: req.firmware,
            disks: req.disks,
            nics: req.nics,
            gpus: req.gpus,
            cdrom,
            description: req.description,
            created_at: now_ts(),
            updated_at: None,
        };

        self.define(&vm).await?;

        let mut vm = vm;
        if req.start {
            self.virsh(&["start", &vm.id]).await?;
            vm.state = VmState::Running;
        }
        self.store.put(&vm.id, &vm).await?;
        Ok(vm)
    }

    pub async fn update(&self, id: &str, req: UpdateVmRequest) -> ApiResult<Vm> {
        let mut vm = self.get_stored(id).await?;
        let old_name = vm.name.clone();

        if let Some(name) = req.name {
            // Keep the rename target path/domain-name safe, mirroring create.
            crate::services::ensure_safe_id(&name)?;
            vm.name = name;
        }
        if let Some(vcpus) = req.vcpus {
            if vcpus == 0 {
                return Err(AppError::validation("vcpus must be >= 1"));
            }
            vm.vcpus = vcpus;
        }
        if let Some(mem) = req.memory_mib {
            if mem == 0 {
                return Err(AppError::validation("memory_mib must be >= 1"));
            }
            vm.memory_mib = mem;
        }

        // Firmware, disk and NIC changes rewrite the guest hardware, so they are
        // only allowed while the VM is stopped.
        let hardware_change = req.firmware.is_some() || req.disks.is_some() || req.nics.is_some();
        if hardware_change {
            self.require_stopped(&vm, "changing its firmware, disks or NICs")
                .await?;
        }
        if let Some(firmware) = req.firmware {
            vm.firmware = firmware;
        }
        if let Some(nics) = req.nics {
            vm.nics = nics;
        }
        if let Some(disks) = req.disks {
            // `ensure_zvol` is idempotent: it reuses a dataset that already exists
            // and only creates a zvol for a genuinely new disk, so calling it for
            // every disk in the set provisions the additions and leaves existing
            // disks untouched. Removing a disk from the set never destroys its data.
            for disk in &disks {
                self.ensure_zvol(disk).await?;
            }
            vm.disks = disks;
        }

        if req.description.is_some() {
            vm.description = req.description;
        }
        // Eject takes precedence over attach; otherwise a provided cdrom path is
        // validated against the ISO library and attached/replaced.
        if req.eject_cdrom.unwrap_or(false) {
            vm.cdrom = None;
        } else if let Some(path) = req.cdrom {
            vm.cdrom = Some(self.resolve_iso(&path).await?);
        }

        // A rename must happen before the redefine (libvirt keys the domain by
        // uuid+name) and requires the domain to be inactive.
        if vm.name != old_name {
            self.virsh(&["domrename", &vm.id, &vm.name])
                .await
                .map_err(|_| AppError::conflict("stop the VM before renaming it"))?;
        }
        self.define(&vm).await?;

        vm.updated_at = Some(now_ts());
        self.store.put(&vm.id, &vm).await?;
        self.get(id).await
    }

    pub async fn delete(&self, id: &str) -> ApiResult<()> {
        // Must exist as a DaygleVE resource first.
        let _ = self.get_stored(id).await?;
        // Force off if running, then remove the persistent definition. Both are
        // best-effort: a domain that is already gone is not an error. Disks
        // (zvols) are intentionally left intact.
        let _ = self.virsh_opt(&["destroy", id]).await;
        let _ = self.virsh_opt(&["undefine", id, "--nvram"]).await;
        self.store.delete(id).await?;
        Ok(())
    }

    pub async fn power(&self, id: &str, action: VmPowerAction) -> ApiResult<Vm> {
        let mut vm = self.get_stored(id).await?;
        let subcommand = match action {
            VmPowerAction::Start => "start",
            VmPowerAction::Shutdown => "shutdown",
            VmPowerAction::Stop => "destroy",
            VmPowerAction::Reboot => "reboot",
            VmPowerAction::Reset => "reset",
            VmPowerAction::Pause => "suspend",
            VmPowerAction::Resume => "resume",
        };
        self.virsh(&[subcommand, id]).await?;

        vm.state = self.live_state(id).await.unwrap_or(vm.state);
        vm.updated_at = Some(now_ts());
        self.store.put(id, &vm).await?;
        Ok(vm)
    }

    pub async fn console(&self, id: &str) -> ApiResult<ConsoleTicket> {
        let _ = self.get_stored(id).await?;
        // `virsh vncdisplay` prints e.g. `127.0.0.1:0` or `:0` (display N ->
        // TCP port 5900+N). A non-running domain has no display.
        let display = self
            .virsh(&["vncdisplay", id])
            .await
            .map_err(|_| AppError::conflict("start the VM to open a console"))?;
        let vnc_addr = parse_vnc_display(display.trim())
            .ok_or_else(|| AppError::hypervisor("could not resolve the VM's VNC port"))?;

        let ticket = new_id();
        {
            let mut tickets = self.tickets.write().expect("ticket lock");
            let now = Instant::now();
            // Opportunistically drop expired tickets so the map can't grow
            // unbounded from tickets that were minted but never redeemed.
            tickets.retain(|_, t| t.expires_at > now);
            tickets.insert(
                ticket.clone(),
                Ticket {
                    vm_id: id.to_string(),
                    vnc_addr,
                    expires_at: now + TICKET_TTL,
                },
            );
        }

        Ok(ConsoleTicket {
            websocket_path: format!("/api/v1/vms/{id}/console/ws?ticket={ticket}"),
            ticket,
            expires_at: (chrono::Utc::now() + chrono::Duration::from_std(TICKET_TTL).unwrap())
                .to_rfc3339(),
        })
    }

    /// Validate and consume a console ticket, returning the VNC socket address
    /// to proxy to. One-time: the ticket is removed on success.
    pub fn redeem_ticket(&self, vm_id: &str, ticket: &str) -> ApiResult<String> {
        let mut tickets = self.tickets.write().expect("ticket lock");
        match tickets.get(ticket) {
            Some(t) if t.vm_id == vm_id && t.expires_at > Instant::now() => {
                let addr = t.vnc_addr.clone();
                tickets.remove(ticket);
                Ok(addr)
            }
            _ => Err(AppError::unauthorized("invalid or expired console ticket")),
        }
    }

    // --- snapshots -------------------------------------------------------

    /// List the VM's snapshots, one entry per snapshot name taken across the
    /// VM's disks. `used_bytes` is summed over the per-disk snapshots.
    pub async fn list_snapshots(&self, id: &str) -> ApiResult<Vec<VmSnapshot>> {
        let vm = self.get_stored(id).await?;
        let mut by_name: BTreeMap<String, VmSnapshot> = BTreeMap::new();
        for dataset in snapshot_datasets(&vm)? {
            // `-d 1` limits to the dataset's own snapshots; `-p` gives raw bytes
            // and a unix `creation`. A dataset that exists but has no snapshots
            // lists cleanly (empty output), so a *non-zero* exit is either a
            // not-yet-provisioned dataset (skip) or a genuine failure — a missing
            // `zfs` binary (dev host) yields `Ok(None)`, also nothing to list.
            let out = match command::run_optional(
                "zfs",
                &[
                    "list",
                    "-H",
                    "-p",
                    "-t",
                    "snapshot",
                    "-d",
                    "1",
                    "-o",
                    "name,used,creation,daygleve:description",
                    dataset,
                ],
            )
            .await
            {
                Ok(Some(o)) => o,
                Ok(None) => continue,
                // Don't hide permission/transient errors as "no snapshots"; only
                // a dataset that simply doesn't exist yet is safe to skip.
                Err(e) if is_missing_dataset(&e) => continue,
                Err(e) => return Err(e),
            };
            for line in out.lines() {
                let mut cols = line.split('\t');
                let full = cols.next().unwrap_or_default();
                let used = cols.next().unwrap_or("0").parse::<u64>().unwrap_or(0);
                let creation = cols.next().unwrap_or("0").parse::<i64>().unwrap_or(0);
                let desc = cols.next().unwrap_or("-");
                let Some((_, tag)) = full.split_once('@') else {
                    continue;
                };
                let entry = by_name
                    .entry(tag.to_string())
                    .or_insert_with(|| VmSnapshot {
                        name: tag.to_string(),
                        used_bytes: 0,
                        description: None,
                        created_at: ts_from_unix(creation),
                    });
                entry.used_bytes = entry.used_bytes.saturating_add(used);
                // Take the description from whichever disk carries one, rather than
                // letting an unset (`-`) first disk mask a later disk's value.
                if entry.description.is_none() && desc != "-" && !desc.is_empty() {
                    entry.description = Some(desc.to_string());
                }
            }
        }
        Ok(by_name.into_values().collect())
    }

    /// Snapshot every one of the VM's disks under a single name. Works while the
    /// VM is running (ZFS snapshots are crash-consistent); rollback is the guarded
    /// operation, not capture.
    pub async fn create_snapshot(
        &self,
        id: &str,
        req: CreateVmSnapshotRequest,
    ) -> ApiResult<VmSnapshot> {
        let vm = self.get_stored(id).await?;
        let tag = ensure_safe_snapshot(&req.name)?;
        let datasets = snapshot_datasets(&vm)?;
        if datasets.is_empty() {
            return Err(AppError::validation("the VM has no disks to snapshot"));
        }
        if self.list_snapshots(id).await?.iter().any(|s| s.name == tag) {
            return Err(AppError::conflict(format!(
                "a snapshot named {tag:?} already exists"
            )));
        }
        // One `zfs snapshot` call over all disks is atomic across datasets of the
        // same pool, so the set captures a single point in time.
        let targets: Vec<String> = datasets.iter().map(|d| format!("{d}@{tag}")).collect();
        let mut args: Vec<&str> = vec!["snapshot"];
        args.extend(targets.iter().map(String::as_str));
        if let Err(e) = command::run_ok("zfs", &args).await {
            // The pre-check above narrows the window, but a concurrent request can
            // still win the race; surface that as a 409 rather than a 502.
            if is_already_exists(&e) {
                return Err(AppError::conflict(format!(
                    "a snapshot named {tag:?} already exists"
                )));
            }
            return Err(e);
        }
        if let Some(desc) = req.description.as_deref().filter(|d| !d.trim().is_empty()) {
            let prop = format!("daygleve:description={desc}");
            for target in &targets {
                // The snapshot is already captured; a failed annotation must not
                // fail the whole operation.
                let _ = command::run_ok("zfs", &["set", &prop, target]).await;
            }
        }
        self.list_snapshots(id)
            .await?
            .into_iter()
            .find(|s| s.name == tag)
            .ok_or_else(|| AppError::internal("snapshot created but could not be read back"))
    }

    /// Roll every disk back to the named snapshot. Destructive of any newer
    /// snapshots (`zfs rollback -r`) and only allowed while the VM is stopped.
    pub async fn rollback_snapshot(&self, id: &str, name: &str) -> ApiResult<()> {
        let vm = self.get_stored(id).await?;
        let tag = ensure_safe_snapshot(name)?;
        self.require_stopped(&vm, "rolling back a snapshot").await?;
        if !self.list_snapshots(id).await?.iter().any(|s| s.name == tag) {
            return Err(AppError::not_found(format!("no snapshot named {tag:?}")));
        }
        for dataset in snapshot_datasets(&vm)? {
            let target = format!("{dataset}@{tag}");
            command::run_ok("zfs", &["rollback", "-r", &target]).await?;
        }
        Ok(())
    }

    /// Delete the named snapshot from every disk it covers.
    pub async fn delete_snapshot(&self, id: &str, name: &str) -> ApiResult<()> {
        let vm = self.get_stored(id).await?;
        let tag = ensure_safe_snapshot(name)?;
        if !self.list_snapshots(id).await?.iter().any(|s| s.name == tag) {
            return Err(AppError::not_found(format!("no snapshot named {tag:?}")));
        }
        for dataset in snapshot_datasets(&vm)? {
            let target = format!("{dataset}@{tag}");
            command::run_ok("zfs", &["destroy", &target]).await?;
        }
        Ok(())
    }

    // --- internals -------------------------------------------------------

    async fn get_stored(&self, id: &str) -> ApiResult<Vm> {
        self.store
            .get(id)
            .await?
            .ok_or_else(|| AppError::not_found(format!("vm {id} not found")))
    }

    /// Live power state from libvirt, or `None` if it can't be determined
    /// (libvirt absent, domain undefined) so the caller keeps the stored state.
    async fn live_state(&self, id: &str) -> Option<VmState> {
        match command::run_optional("virsh", &["-c", CONNECT, "domstate", id]).await {
            Ok(Some(s)) => Some(map_vm_state(s.trim())),
            _ => None,
        }
    }

    /// True only when virsh is installed but the libvirt connection is unusable —
    /// the one case where an unreadable domain state might be hiding a running VM.
    /// A missing virsh binary (`Ok(None)`) means there is no hypervisor at all, and
    /// a healthy connection (`Ok(Some)`) means an unreadable domain is simply not
    /// defined; both are safe, so only a connection error (`Err`) returns true.
    async fn hypervisor_unreachable(&self) -> bool {
        command::run_optional("virsh", &["-c", CONNECT, "hostname"])
            .await
            .is_err()
    }

    /// Guard operations that must not run against live guest hardware (hardware
    /// edits, snapshot rollback): require the VM to be conclusively stopped, and
    /// fail closed when the live state can't be read but the hypervisor is
    /// reachable-but-broken (a running domain could be hidden). `action` names
    /// the operation for the 409 message, e.g. "rolling back a snapshot".
    async fn require_stopped(&self, vm: &Vm, action: &str) -> ApiResult<()> {
        match self.live_state(&vm.id).await {
            Some(VmState::Stopped) => Ok(()),
            Some(_) => Err(AppError::conflict(format!("stop the VM before {action}"))),
            None => {
                if self.hypervisor_unreachable().await {
                    Err(AppError::conflict(
                        "cannot confirm the VM is stopped (hypervisor unreachable); try again",
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Write the domain XML and (re)define it in libvirt.
    async fn define(&self, vm: &Vm) -> ApiResult<()> {
        // vm.id is a backend-minted UUID, but validate before it reaches a path.
        crate::services::ensure_safe_id(&vm.id)?;
        let xml = domain_xml(vm);
        let dir = self.config.state_dir.join("tmp");
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| AppError::internal(format!("create {}: {e}", dir.display())))?;
        let path = dir.join(format!("{}.xml", vm.id));
        tokio::fs::write(&path, xml)
            .await
            .map_err(|e| AppError::internal(format!("write {}: {e}", path.display())))?;
        let path_str = path.to_string_lossy().into_owned();
        let result = self.virsh(&["define", &path_str]).await;
        let _ = tokio::fs::remove_file(&path).await;
        result.map(|_| ())
    }

    /// Create a zvol for a disk if it does not already exist.
    async fn ensure_zvol(&self, disk: &VmDisk) -> ApiResult<()> {
        if disk.dataset.trim().is_empty() || disk.size_gib == 0 {
            return Ok(());
        }
        if disk.dataset.starts_with('-') {
            // Prevent the dataset from being misparsed as a `zfs` flag.
            return Err(AppError::validation("disk dataset must not start with '-'"));
        }
        // Reuse an existing dataset; otherwise create it. Distinguish "zfs not
        // installed" (fail fast — we must never define a domain pointing at a
        // zvol that was never provisioned) from "dataset does not exist yet".
        match command::run_optional("zfs", &["list", "-H", "-o", "name", &disk.dataset]).await {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {
                return Err(AppError::hypervisor(
                    "zfs is not installed; cannot provision the VM disk",
                ))
            }
            Err(_) => {} // dataset does not exist yet — create it below
        }
        let size = format!("{}G", disk.size_gib);
        command::run_ok("zfs", &["create", "-V", &size, &disk.dataset]).await
    }

    /// Enumerate the installer/live ISOs available to the node: the built-in
    /// library (`config.iso_dir`, non-recursive, tagged `local`) plus every
    /// currently-mounted network share (scanned recursively, tagged with the
    /// share's name). A missing/unreadable root contributes nothing rather than
    /// erroring, so a fresh node simply shows "no ISOs yet".
    pub async fn list_isos(&self) -> ApiResult<Vec<IsoImage>> {
        let mut isos = Vec::new();

        // Built-in local library: flat, no recursion.
        scan_iso_dir(&self.config.iso_dir, "local", 0, &mut isos).await;

        // Network shares: a share can organise ISOs into subdirectories, so
        // walk each mount point to a bounded depth.
        for (name, root) in self.shares.iso_roots().await {
            scan_iso_dir(&root, &name, ISO_SCAN_DEPTH, &mut isos).await;
        }

        isos.sort_by(|a, b| a.storage.cmp(&b.storage).then_with(|| a.name.cmp(&b.name)));
        Ok(isos)
    }

    /// Validate a requested install-media path: it must be one of the ISOs the
    /// node actually offers. Returning the enumerated path (never the raw input)
    /// keeps a VM from being pointed at an arbitrary host file.
    async fn resolve_iso(&self, requested: &str) -> ApiResult<String> {
        let requested = requested.trim();
        if requested.is_empty() {
            return Err(AppError::validation("cdrom must not be empty"));
        }
        self.list_isos()
            .await?
            .into_iter()
            .find(|iso| iso.path == requested)
            .map(|iso| iso.path)
            .ok_or_else(|| {
                AppError::validation(
                    "cdrom is not an available ISO image (see GET /vms/iso-images)",
                )
            })
    }

    async fn virsh(&self, args: &[&str]) -> ApiResult<String> {
        let mut full = vec!["-c", CONNECT];
        full.extend_from_slice(args);
        command::run("virsh", &full).await
    }

    async fn virsh_opt(&self, args: &[&str]) -> ApiResult<Option<String>> {
        let mut full = vec!["-c", CONNECT];
        full.extend_from_slice(args);
        command::run_optional("virsh", &full).await
    }
}

/// libvirt connection URI (system instance; the backend runs as root).
const CONNECT: &str = "qemu:///system";

/// Collect `*.iso` regular files under `root` (up to `max_depth` levels deep;
/// 0 means the root only), appending an [`IsoImage`] tagged with `storage` for
/// each. Symlinks are never followed — a plain directory entry that is a
/// symlink is skipped — so an ISO can never resolve outside the scanned root.
/// Unreadable directories are silently skipped so one bad share can't fail the
/// whole listing.
async fn scan_iso_dir(
    root: &std::path::Path,
    storage: &str,
    max_depth: u32,
    out: &mut Vec<IsoImage>,
) {
    // Iterative walk over (directory, depth) to avoid async recursion.
    let mut stack = vec![(root.to_path_buf(), 0u32)];
    while let Some((dir, depth)) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(e) => e,
            Err(_) => continue,
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            // The entry's own type does not follow symlinks: a symlink reports
            // neither is_dir nor is_file here, so it is skipped entirely.
            let file_type = match entry.file_type().await {
                Ok(t) => t,
                Err(_) => continue,
            };
            let path = entry.path();
            if file_type.is_dir() {
                if depth < max_depth {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !file_type.is_file() {
                continue; // symlink, socket, device, …
            }
            let is_iso = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("iso"));
            if !is_iso {
                continue;
            }
            let meta = match tokio::fs::metadata(&path).await {
                Ok(m) => m,
                Err(_) => continue,
            };
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            out.push(IsoImage {
                name,
                path: path.to_string_lossy().into_owned(),
                size_bytes: meta.len(),
                storage: storage.to_string(),
            });
        }
    }
}

fn summary_of(vm: &Vm) -> VmSummary {
    VmSummary {
        id: vm.id.clone(),
        name: vm.name.clone(),
        state: vm.state,
        vcpus: vm.vcpus,
        memory_mib: vm.memory_mib,
        created_at: vm.created_at.clone(),
    }
}

fn map_vm_state(s: &str) -> VmState {
    match s.trim() {
        "running" | "idle" => VmState::Running,
        "paused" | "pmsuspended" => VmState::Paused,
        "in shutdown" => VmState::Transitioning,
        "shut off" => VmState::Stopped,
        "crashed" => VmState::Error,
        _ => VmState::Stopped,
    }
}

/// Format a unix epoch (seconds, from ZFS `creation -p`) as the schema's RFC-3339
/// timestamp. Falls back to the current time only for a `secs` that lands outside
/// the representable range (a non-numeric `creation` was already coerced to 0 by
/// the caller's `parse().unwrap_or(0)`, which is in range).
fn ts_from_unix(secs: i64) -> daygleve_schema::common::Timestamp {
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(now_ts)
}

/// The VM's non-empty disk datasets, each validated as a ZFS dataset path, so the
/// `dataset@tag` targets handed to `zfs` are always built from sanitized input.
fn snapshot_datasets(vm: &Vm) -> ApiResult<Vec<&str>> {
    vm.disks
        .iter()
        .map(|d| d.dataset.trim())
        .filter(|d| !d.is_empty())
        .map(ensure_safe_dataset)
        .collect()
}

/// Validate a ZFS dataset path and return it, so callers build `zfs` arguments
/// from the sanitizer's output (path/flag-injection barrier). Allows the ZFS
/// dataset charset — letters, digits, and the punctuation `_`, `-`, `.`, `:`,
/// `/` — while rejecting an empty path, a leading `-` (which a host CLI could
/// read as a flag) and any `..` traversal component.
fn ensure_safe_dataset(dataset: &str) -> ApiResult<&str> {
    let ok = !dataset.is_empty()
        && !dataset.starts_with('-')
        && !dataset.split('/').any(|seg| seg == ".." || seg.is_empty())
        && dataset
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'/'));
    if ok {
        Ok(dataset)
    } else {
        Err(AppError::validation(format!(
            "invalid dataset path: {dataset:?}"
        )))
    }
}

/// Validate a ZFS snapshot tag and return it, so callers build the
/// `dataset@tag` from the sanitizer's output (path/flag-injection barrier).
/// Accepts the ZFS-safe set — letters, digits, and the punctuation `_`, `-`,
/// `.`, `:` (no spaces) — and rejects a leading `-` that a host CLI could read
/// as a flag.
fn ensure_safe_snapshot(name: &str) -> ApiResult<&str> {
    let ok = !name.is_empty()
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'));
    if ok {
        Ok(name)
    } else {
        Err(AppError::validation(format!(
            "invalid snapshot name: {name:?}"
        )))
    }
}

/// True when a `zfs` error indicates the target dataset simply does not exist,
/// as opposed to a permission or transient failure we must not hide.
fn is_missing_dataset(e: &AppError) -> bool {
    let m = e.message().to_ascii_lowercase();
    m.contains("does not exist") || m.contains("dataset does not exist")
}

/// True when a `zfs snapshot` error indicates the snapshot already exists, so a
/// racing create can be reported as a 409 instead of a 502.
fn is_already_exists(e: &AppError) -> bool {
    e.message().to_ascii_lowercase().contains("already exists")
}

/// Parse `virsh vncdisplay` output (`host:N` or `:N`) to a `host:port` socket.
fn parse_vnc_display(display: &str) -> Option<String> {
    let (host, disp) = display.rsplit_once(':')?;
    let n: u16 = disp.trim().parse().ok()?;
    let host = if host.is_empty() { "127.0.0.1" } else { host };
    Some(format!("{host}:{}", 5900 + n))
}

/// Render libvirt domain XML for a VM.
fn domain_xml(vm: &Vm) -> String {
    // When an install ISO is attached, boot order is expressed per-device
    // (`<boot order=…>` on the cdrom and first disk) so the CD-ROM comes first;
    // this is mutually exclusive with the `<os><boot dev=…></os>` form, so the
    // os block only carries a fixed boot device when no CD-ROM is present.
    let has_cdrom = vm.cdrom.is_some();
    let os_boot = if has_cdrom {
        "<bootmenu enable='yes'/>"
    } else {
        "<boot dev='hd'/>"
    };
    let os = match vm.firmware {
        Firmware::Uefi => format!(
            "<os firmware='efi'>\n    <type arch='x86_64' machine='q35'>hvm</type>\n    {os_boot}\n  </os>"
        ),
        Firmware::Bios => format!(
            "<os>\n    <type arch='x86_64' machine='q35'>hvm</type>\n    {os_boot}\n  </os>"
        ),
    };

    // The first disk gets boot priority 2 (after the CD-ROM at 1) when
    // installing; otherwise no explicit per-device order.
    let disks: String = vm
        .disks
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let boot = if has_cdrom && i == 0 { Some(2) } else { None };
            disk_xml(i, d, boot)
        })
        .collect();
    let cdrom: String = vm.cdrom.as_deref().map(cdrom_xml).unwrap_or_default();
    let nics: String = vm.nics.iter().map(nic_xml).collect();
    let hostdevs: String = vm
        .gpus
        .iter()
        .filter_map(|g| pci_hostdev_xml(&g.pci_address))
        .collect();

    let description = vm
        .description
        .as_deref()
        .map(|d| format!("  <description>{}</description>\n", xml_escape(d)))
        .unwrap_or_default();

    format!(
        "<domain type='kvm'>\n  \
        <name>{name}</name>\n  \
        <uuid>{uuid}</uuid>\n\
        {description}  \
        <memory unit='MiB'>{mem}</memory>\n  \
        <currentMemory unit='MiB'>{mem}</currentMemory>\n  \
        <vcpu placement='static'>{vcpus}</vcpu>\n  \
        {os}\n  \
        <features><acpi/><apic/></features>\n  \
        <cpu mode='host-passthrough' check='none'/>\n  \
        <clock offset='utc'/>\n  \
        <on_poweroff>destroy</on_poweroff>\n  \
        <on_reboot>restart</on_reboot>\n  \
        <on_crash>destroy</on_crash>\n  \
        <devices>\n    \
        <emulator>/usr/bin/qemu-system-x86_64</emulator>\n\
        {disks}{cdrom}{nics}{hostdevs}    \
        <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'/>\n    \
        <video><model type='virtio' heads='1'/></video>\n    \
        <memballoon model='virtio'/>\n    \
        <console type='pty'/>\n  \
        </devices>\n\
        </domain>\n",
        name = xml_escape(&vm.name),
        uuid = vm.id,
        description = description,
        mem = vm.memory_mib,
        vcpus = vm.vcpus,
        os = os,
        disks = disks,
        cdrom = cdrom,
        nics = nics,
        hostdevs = hostdevs,
    )
}

fn disk_xml(index: usize, disk: &VmDisk, boot_order: Option<u32>) -> String {
    let (target, bus) = disk_target(disk.bus, index);
    let boot = boot_order
        .map(|o| format!("      <boot order='{o}'/>\n"))
        .unwrap_or_default();
    format!(
        "    <disk type='block' device='disk'>\n      \
        <driver name='qemu' type='raw' cache='none' io='native'/>\n      \
        <source dev='/dev/zvol/{dataset}'/>\n      \
        <target dev='{target}' bus='{bus}'/>\n\
        {boot}    \
        </disk>\n",
        dataset = xml_escape(&disk.dataset),
    )
}

/// A virtual CD-ROM holding an install ISO. Boots first (`<boot order='1'/>`)
/// so a guest OS can be installed onto the (empty) primary disk. Uses a
/// two-letter SATA target (`sdaa`) that sits outside the single-letter scheme
/// data disks use (`sda`..`sdz`), so it can never collide with a data disk.
fn cdrom_xml(iso_path: &str) -> String {
    format!(
        "    <disk type='file' device='cdrom'>\n      \
        <driver name='qemu' type='raw'/>\n      \
        <source file='{iso}'/>\n      \
        <target dev='sdaa' bus='sata'/>\n      \
        <readonly/>\n      \
        <boot order='1'/>\n    \
        </disk>\n",
        iso = xml_escape(iso_path),
    )
}

fn disk_target(bus: DiskBus, index: usize) -> (String, &'static str) {
    let letter = (b'a' + (index as u8 % 26)) as char;
    match bus {
        DiskBus::Virtio => (format!("vd{letter}"), "virtio"),
        DiskBus::Scsi => (format!("sd{letter}"), "scsi"),
        DiskBus::Sata => (format!("sd{letter}"), "sata"),
    }
}

fn nic_xml(nic: &VmNic) -> String {
    let model = match nic.model {
        NicModel::Virtio => "virtio",
        NicModel::E1000 => "e1000",
        NicModel::Rtl8139 => "rtl8139",
    };
    let mac = nic
        .mac
        .as_deref()
        .map(|m| format!("      <mac address='{}'/>\n", xml_escape(m)))
        .unwrap_or_default();
    let vlan = nic
        .vlan
        .map(|tag| format!("      <vlan><tag id='{tag}'/></vlan>\n"))
        .unwrap_or_default();
    format!(
        "    <interface type='bridge'>\n      \
        <source bridge='{bridge}'/>\n\
        {mac}      <model type='{model}'/>\n\
        {vlan}    </interface>\n",
        bridge = xml_escape(&nic.bridge),
    )
}

/// A `<hostdev>` PCI passthrough element from an address like `0000:01:00.0`.
fn pci_hostdev_xml(pci_address: &str) -> Option<String> {
    let (dbs, func) = pci_address.rsplit_once('.')?;
    let mut it = dbs.split(':');
    let domain = it.next()?;
    let bus = it.next()?;
    let slot = it.next()?;
    Some(format!(
        "    <hostdev mode='subsystem' type='pci' managed='yes'>\n      \
        <source><address domain='0x{domain}' bus='0x{bus}' slot='0x{slot}' function='0x{func}'/></source>\n    \
        </hostdev>\n",
    ))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vm() -> Vm {
        Vm {
            id: new_id(),
            name: "web01".to_string(),
            state: VmState::Stopped,
            vcpus: 2,
            memory_mib: 2048,
            firmware: Firmware::Uefi,
            disks: vec![VmDisk {
                dataset: "tank/vms/web01-disk0".to_string(),
                size_gib: 20,
                bus: DiskBus::Virtio,
            }],
            nics: vec![],
            gpus: vec![],
            cdrom: None,
            description: None,
            created_at: now_ts(),
            updated_at: None,
        }
    }

    #[test]
    fn domain_xml_without_cdrom_boots_from_disk() {
        let xml = domain_xml(&sample_vm());
        assert!(xml.contains("<boot dev='hd'/>"), "should boot from disk");
        assert!(!xml.contains("device='cdrom'"), "no cdrom device");
        assert!(!xml.contains("<boot order="), "no per-device boot order");
    }

    #[test]
    fn domain_xml_with_cdrom_boots_from_media_then_disk() {
        let mut vm = sample_vm();
        vm.cdrom = Some("/var/lib/daygleve/isos/debian.iso".to_string());
        let xml = domain_xml(&vm);

        // Per-device boot order replaces the fixed <os><boot dev=…>.
        assert!(!xml.contains("<boot dev='hd'/>"));
        assert!(xml.contains("<bootmenu enable='yes'/>"));

        // The CD-ROM is present, read-only, and first in the boot order.
        assert!(xml.contains("device='cdrom'"));
        assert!(xml.contains("<source file='/var/lib/daygleve/isos/debian.iso'/>"));
        assert!(xml.contains("<readonly/>"));
        // The CD-ROM target sits outside the single-letter data-disk scheme.
        assert!(xml.contains("<target dev='sdaa' bus='sata'/>"));
        assert!(xml.contains("<boot order='1'/>"), "cdrom boots first");
        // The primary disk boots second.
        assert!(xml.contains("<boot order='2'/>"), "disk boots second");
    }

    #[test]
    fn domain_xml_bios_firmware_boot_paths() {
        // BIOS without media: legacy <os> block boots from disk.
        let mut vm = sample_vm();
        vm.firmware = Firmware::Bios;
        let xml = domain_xml(&vm);
        assert!(xml.contains("<os>\n"), "BIOS uses the plain <os> block");
        assert!(!xml.contains("firmware='efi'"), "BIOS is not EFI");
        assert!(xml.contains("<boot dev='hd'/>"), "BIOS boots from disk");

        // BIOS with media: switches to the boot menu + per-device order.
        vm.cdrom = Some("/var/lib/daygleve/isos/debian.iso".to_string());
        let xml = domain_xml(&vm);
        assert!(!xml.contains("firmware='efi'"), "still BIOS");
        assert!(!xml.contains("<boot dev='hd'/>"));
        assert!(xml.contains("<bootmenu enable='yes'/>"));
        assert!(xml.contains("device='cdrom'"));
        assert!(xml.contains("<boot order='1'/>"));
        assert!(xml.contains("<boot order='2'/>"));
    }

    #[test]
    fn snapshot_names_are_validated() {
        // Accept the ZFS-safe set, including a colon.
        for ok in ["daily", "pre-upgrade", "snap_1", "2026.09.04", "backup:1"] {
            assert!(ensure_safe_snapshot(ok).is_ok(), "{ok:?} should be valid");
        }
        // Reject empties, leading '-' (flag injection), path separators and
        // the '@' that separates dataset from tag.
        for bad in ["", "-rf", "a/b", "a@b", "a b", "naïve"] {
            assert!(
                ensure_safe_snapshot(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn dataset_paths_are_validated() {
        for ok in ["tank/vms/web01-disk0", "pool", "a/b/c", "rpool/data:1"] {
            assert!(ensure_safe_dataset(ok).is_ok(), "{ok:?} should be valid");
        }
        // Empty, leading '-', traversal, empty segments and the '@' separator.
        for bad in ["", "-tank/x", "tank/../etc", "tank//x", "tank/x@y", "a b"] {
            assert!(
                ensure_safe_dataset(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn unix_timestamps_render_as_rfc3339() {
        // 1_788_480_000 == 2026-09-04T00:00:00Z.
        let ts = ts_from_unix(1_788_480_000);
        assert!(
            ts.starts_with("2026-09-04T00:00:00"),
            "unexpected timestamp: {ts}"
        );
    }
}
