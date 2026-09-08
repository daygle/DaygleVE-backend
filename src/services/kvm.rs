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
    AttachVmPciRequest, AttachVmUsbRequest, CloneVmRequest, CloudInitRequest, ConsoleTicket,
    CreateVmRequest, CreateVmSnapshotRequest, DiskBus, DisplayProtocol, Firmware, GuestAgentInfo,
    IsoImage, NicModel, ResizeVmDiskRequest, UpdateVmRequest, Vm, VmDisk, VmFirewall,
    VmFirewallAction, VmFirewallDirection, VmNic, VmPowerAction, VmPowerResponse, VmSnapshot,
    VmSnapshotType, VmState, VmSummary,
};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::shares::ShareService;
use crate::services::store::JsonStore;
use crate::services::{
    command, ensure_safe_cidr, ensure_safe_id, ensure_safe_mac, ensure_safe_pci_address,
    ensure_safe_zfs_dataset, new_id, normalize_pool_ref, now_ts, validate_tags,
};

/// How long a console ticket is valid before the client must re-request one.
const TICKET_TTL: Duration = Duration::from_secs(60);

/// How many directory levels deep to search a network share for ISOs. Deep
/// enough for the common `iso/` or `template/iso/` layouts without walking an
/// arbitrarily large tree.
const ISO_SCAN_DEPTH: u32 = 4;

/// Prefix for the internal base snapshots that back linked clones. Snapshots
/// with this tag are system-managed, so they're hidden from the user-facing VM
/// snapshot list.
const CLONE_SNAPSHOT_PREFIX: &str = "daygleve-clone-";

/// What a redeemed console ticket connects the browser to.
pub enum ConsoleTarget {
    /// A VNC TCP socket address (`host:port`) — the graphical console.
    Vnc(String),
    /// A serial console pty device path (`/dev/pts/<n>`) — the text console.
    Serial(String),
}

/// A pending console ticket bound to a domain's console endpoint.
struct Ticket {
    vm_id: String,
    target: ConsoleTarget,
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
        validate_vm_request(&req)?;
        // A template is a clone-only golden image; it is never powered on, so
        // reject the contradictory "create as template and start it" request.
        if req.template && req.start {
            return Err(AppError::validation("a template cannot be started"));
        }
        let nics = normalize_nics(req.nics)?;
        validate_gpu_assignments(&req.gpus)?;
        validate_usb_assignments(&req.usb_devices)?;
        validate_pci_assignments(&req.pci_devices)?;

        // Validate any requested install ISO against the node's library before
        // it reaches libvirt (prevents pointing a VM at an arbitrary host file).
        let cdrom = match req.cdrom {
            Some(path) => Some(self.resolve_iso(&path).await?),
            None => None,
        };

        // Provision a zvol for each disk. Existing datasets are reused; newly
        // created zvols are tracked so later failures can be rolled back.
        let mut created_zvols = Vec::new();
        for disk in &req.disks {
            if self.ensure_zvol(disk).await? {
                created_zvols.push(disk.dataset.trim().to_string());
            }
        }

        // Cloud-init provisioning: generate a NoCloud seed ISO up front so its
        // path can land in the domain XML. Tracked for rollback alongside the
        // zvols (it is a file, removed by path, not a dataset).
        let cloud_init_iso = match req.cloud_init.as_ref() {
            Some(ci) => match self.create_cloud_init_iso(&req.name, ci).await {
                Ok(path) => Some(path),
                Err(e) => {
                    self.cleanup_created_zvols(&created_zvols).await;
                    return Err(e);
                }
            },
            None => None,
        };

        let vm = Vm {
            id: new_id(),
            name: req.name,
            state: VmState::Stopped,
            vcpus: req.vcpus,
            memory_mib: req.memory_mib,
            firmware: req.firmware,
            display: req.display,
            disks: req.disks,
            nics,
            gpus: req.gpus,
            usb_devices: req.usb_devices,
            pci_devices: req.pci_devices,
            cdrom,
            cloud_init_iso,
            description: req.description,
            guest_agent: req.guest_agent,
            firewall: req.firewall,
            // A template never runs, so it is never autostarted regardless of the
            // requested flag.
            template: req.template,
            autostart: req.autostart && !req.template,
            startup_order: req.startup_order,
            tags: validate_tags(req.tags)?,
            pool: normalize_pool_ref(req.pool),
            created_at: now_ts(),
            updated_at: None,
        };

        if let Err(e) = self.define(&vm).await {
            self.cleanup_created_zvols(&created_zvols).await;
            if let Some(iso) = &vm.cloud_init_iso {
                let _ = tokio::fs::remove_file(iso).await;
            }
            return Err(e);
        }

        // Apply the firewall after a successful define; on failure, tear the
        // definition back down like the other post-define failures.
        if vm.firewall.enabled {
            if let Err(e) = self.apply_firewall(&vm.id, &vm, true).await {
                let _ = self.virsh_opt(&["undefine", &vm.id, "--nvram"]).await;
                self.cleanup_created_zvols(&created_zvols).await;
                if let Some(iso) = &vm.cloud_init_iso {
                    let _ = tokio::fs::remove_file(iso).await;
                }
                return Err(e);
            }
        }

        let mut vm = vm;
        if req.start {
            if let Err(e) = self.virsh(&["start", &vm.id]).await {
                let _ = self.virsh_opt(&["undefine", &vm.id, "--nvram"]).await;
                self.cleanup_created_zvols(&created_zvols).await;
                return Err(e);
            }
            vm.state = VmState::Running;
        }
        if let Err(e) = self.store.put(&vm.id, &vm).await {
            let _ = self.virsh_opt(&["destroy", &vm.id]).await;
            let _ = self.virsh_opt(&["undefine", &vm.id, "--nvram"]).await;
            self.cleanup_created_zvols(&created_zvols).await;
            return Err(e);
        }
        Ok(vm)
    }

    pub async fn update(&self, id: &str, req: UpdateVmRequest) -> ApiResult<Vm> {
        let mut vm = self.get_stored(id).await?;
        let old_name = vm.name.clone();

        if let Some(name) = req.name.as_deref() {
            ensure_safe_id(name)?;
            if name != old_name {
                let existing: Vec<Vm> = self.store.list().await?;
                if existing
                    .iter()
                    .any(|other| other.id != id && other.name == name)
                {
                    return Err(AppError::conflict(format!(
                        "a VM named {name:?} already exists"
                    )));
                }
            }
        }

        if let Some(name) = req.name {
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
        // only allowed while the VM is stopped. Guest-agent enablement, firewall
        // and cloud-init changes likewise rewrite the domain XML.
        if let Some(disks) = req.disks.as_ref() {
            validate_disks(disks)?;
        }
        if let Some(nics) = req.nics.as_ref() {
            validate_nics(nics)?;
        }
        if let Some(fw) = req.firewall.as_ref() {
            validate_firewall(fw)?;
        }
        let hardware_change = req.firmware.is_some()
            || req.display.is_some()
            || req.disks.is_some()
            || req.nics.is_some()
            || req.guest_agent.is_some()
            || req.cloud_init.is_some();
        if hardware_change {
            self.require_stopped(
                &vm,
                "changing its firmware, display, disks, NICs, guest agent or cloud-init",
            )
            .await?;
        }
        if let Some(firmware) = req.firmware {
            vm.firmware = firmware;
        }
        if let Some(display) = req.display {
            vm.display = display;
        }
        if let Some(nics) = req.nics {
            vm.nics = normalize_nics(nics)?;
        }
        if let Some(disks) = req.disks {
            // `ensure_zvol` is idempotent: it reuses a dataset that already exists
            // and only creates a zvol for a genuinely new disk, so calling it for
            // every disk in the set provisions the additions and leaves existing
            // disks untouched. Removing a disk from the set never destroys its data.
            for disk in &disks {
                let _ = self.ensure_zvol(disk).await?;
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
        if let Some(guest_agent) = req.guest_agent {
            vm.guest_agent = guest_agent;
        }
        if let Some(firewall) = req.firewall {
            vm.firewall = firewall;
        }
        if let Some(cloud_init) = req.cloud_init {
            // Regenerate the seed ISO from the new request; the old one (if any)
            // is replaced once the new file exists.
            let new_iso = self.create_cloud_init_iso(&vm.name, &cloud_init).await?;
            let old_iso = vm.cloud_init_iso.replace(new_iso);
            if let Some(old) = old_iso {
                let _ = tokio::fs::remove_file(&old).await;
            }
        }

        if let Some(startup_order) = req.startup_order {
            vm.startup_order = Some(startup_order);
        }
        if let Some(tags) = req.tags {
            vm.tags = validate_tags(tags)?;
        }
        if let Some(pool) = req.pool {
            // Existence of a non-empty pool is validated at the API layer; here
            // we just apply it, treating an empty value as "remove from pool".
            vm.pool = normalize_pool_ref(Some(pool));
        }
        if let Some(autostart) = req.autostart {
            vm.autostart = autostart;
        }
        if let Some(template) = req.template {
            // Converting a running VM into a template makes no sense (a template
            // is never running), so require it stopped first. A template is also
            // never autostarted.
            if template && !vm.template {
                self.require_stopped(&vm, "converting it to a template")
                    .await?;
            }
            vm.template = template;
            if template {
                vm.autostart = false;
            }
        }

        // A rename must happen before the redefine (libvirt keys the domain by
        // uuid+name) and requires the domain to be inactive.
        if vm.name != old_name {
            self.virsh(&["domrename", &vm.id, &vm.name])
                .await
                .map_err(|_| AppError::conflict("stop the VM before renaming it"))?;
        }
        self.define(&vm).await?;

        // Keep the host-side firewall in sync with the (possibly new) config.
        // Apply-after-define; a failed apply must not leave the stored config
        // claiming rules that are not active, so failures propagate.
        self.apply_firewall(&vm.id, &vm, vm.firewall.enabled)
            .await?;

        vm.updated_at = Some(now_ts());
        self.store.put(&vm.id, &vm).await?;
        self.get(id).await
    }

    pub async fn delete(&self, id: &str) -> ApiResult<()> {
        // Must exist as a DaygleVE resource first.
        let vm = self.get_stored(id).await?;
        // If the VM has firewall rules, tear them down before removing the domain.
        if vm.firewall.enabled {
            let _ = self.apply_firewall(id, &vm, false).await;
        }
        // Force off if running, then remove the persistent definition. Both are
        // best-effort: a domain that is already gone is not an error. Disks
        // (zvols) are intentionally left intact.
        let _ = self.virsh_opt(&["destroy", id]).await;
        let _ = self.virsh_opt(&["undefine", id, "--nvram"]).await;
        self.store.delete(id).await?;
        Ok(())
    }

    /// Clone a VM: ZFS-clone each of the source's disks (from a fresh base
    /// snapshot) into new datasets, then define a new stopped domain with a new
    /// id, the source's compute/hardware, and freshly-generated NIC MACs. GPU
    /// passthrough and any attached install ISO are dropped. `full` promotes the
    /// cloned disks so they no longer depend on the source snapshot.
    pub async fn clone(&self, id: &str, req: CloneVmRequest) -> ApiResult<Vm> {
        let src = self.get_stored(id).await?;
        if req.name.trim().is_empty() {
            return Err(AppError::validation("name must not be empty"));
        }
        crate::services::ensure_safe_id(&req.name)?;
        // libvirt domain names are unique; reject a name another VM already uses.
        let existing: Vec<Vm> = self.store.list().await?;
        if existing.iter().any(|v| v.name == req.name) {
            return Err(AppError::conflict(format!(
                "a VM named {:?} already exists",
                req.name
            )));
        }

        let new_id = new_id();
        // A short, unique, ZFS-safe base-snapshot tag. The reserved prefix marks
        // it as a clone base so it stays out of the user-facing snapshot list.
        let short = new_id.replace('-', "");
        let tag = format!("{CLONE_SNAPSHOT_PREFIX}{}", &short[..12]);

        // A disk with no dataset would clone into an invalid domain (domain_xml
        // always renders a zvol source), so fail fast rather than silently
        // dropping it and producing a partial hardware copy.
        if src.disks.iter().any(|d| d.dataset.trim().is_empty()) {
            return Err(AppError::validation(
                "the source VM has a disk with no dataset; cannot clone",
            ));
        }
        // Plan the destination datasets: same parent as each source disk, with a
        // leaf derived from the new VM name. Validate every path through the
        // dataset barrier before it reaches `zfs`.
        let mut new_disks: Vec<VmDisk> = Vec::new();
        let mut planned: Vec<(String, String)> = Vec::new(); // (src_dataset, new_dataset)
        for (i, disk) in src.disks.iter().enumerate() {
            let src_ds = ensure_safe_dataset(disk.dataset.trim())?;
            let parent = src_ds.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
            let new_ds = if parent.is_empty() {
                format!("{}-disk{i}", req.name)
            } else {
                format!("{parent}/{}-disk{i}", req.name)
            };
            ensure_safe_dataset(&new_ds)?;
            planned.push((src_ds.to_string(), new_ds.clone()));
            new_disks.push(VmDisk {
                dataset: new_ds,
                size_gib: disk.size_gib,
                bus: disk.bus,
            });
        }

        // Snapshot every source disk together as the clone base (crash-consistent
        // if the source is running, like the snapshot endpoint).
        if !planned.is_empty() {
            let bases: Vec<String> = planned.iter().map(|(s, _)| format!("{s}@{tag}")).collect();
            let mut args: Vec<&str> = vec!["snapshot"];
            args.extend(bases.iter().map(String::as_str));
            command::run_ok("zfs", &args).await?;
        }

        // Clone (and optionally promote) each disk, tearing everything down on
        // any failure so a partial clone never lingers.
        let mut created: Vec<String> = Vec::new();
        for (src_ds, new_ds) in &planned {
            let base = format!("{src_ds}@{tag}");
            if let Err(e) = command::run_ok("zfs", &["clone", &base, new_ds]).await {
                self.cleanup_clone(&planned, &created, &tag).await;
                return Err(e);
            }
            created.push(new_ds.clone());
            if req.full {
                if let Err(e) = command::run_ok("zfs", &["promote", new_ds]).await {
                    self.cleanup_clone(&planned, &created, &tag).await;
                    return Err(e);
                }
            }
        }

        // A full clone is meant to be independent: `zfs promote` moved each base
        // snapshot onto the clone, where it's no longer needed, so best-effort
        // destroy it rather than leave a hidden snapshot pinning space.
        if req.full {
            for new_ds in &created {
                let _ = command::run_ok("zfs", &["destroy", &format!("{new_ds}@{tag}")]).await;
            }
        }

        let clone_vm = Vm {
            id: new_id,
            name: req.name,
            state: VmState::Stopped,
            vcpus: src.vcpus,
            memory_mib: src.memory_mib,
            firmware: src.firmware,
            display: src.display,
            disks: new_disks,
            // Give each NIC a freshly-generated MAC (recorded in the VM), so the
            // clone never inherits the source's MAC and we always know what it is.
            nics: src
                .nics
                .iter()
                .map(|n| VmNic {
                    mac: Some(generate_mac()),
                    ..n.clone()
                })
                .collect(),
            gpus: Vec::new(),        // passthrough can't be shared
            usb_devices: Vec::new(), // nor can USB passthrough
            pci_devices: Vec::new(), // nor can PCI passthrough
            cdrom: None,             // install media isn't carried over
            cloud_init_iso: None,
            description: req.description.or(src.description.clone()),
            guest_agent: false,
            firewall: VmFirewall::default(),
            // A clone is a fresh, runnable VM — never a template — and does not
            // inherit the source's autostart intent.
            template: false,
            autostart: false,
            startup_order: None,
            tags: src.tags.clone(),
            pool: src.pool.clone(),
            created_at: now_ts(),
            updated_at: None,
        };
        if let Err(e) = self.define(&clone_vm).await {
            self.cleanup_clone(&planned, &created, &tag).await;
            return Err(e);
        }
        self.store.put(&clone_vm.id, &clone_vm).await?;
        Ok(clone_vm)
    }

    /// Best-effort teardown of a partially-created clone: destroy any clone
    /// datasets already made, then the base snapshots on the source disks.
    async fn cleanup_clone(&self, planned: &[(String, String)], created: &[String], tag: &str) {
        for new_ds in created {
            let _ = command::run_ok("zfs", &["destroy", "-r", new_ds]).await;
        }
        for (src_ds, _) in planned {
            let _ = command::run_ok("zfs", &["destroy", &format!("{src_ds}@{tag}")]).await;
        }
    }

    /// Compare persisted VM records to live libvirt domains, returning findings
    /// about VMs that exist in one but not the other.
    ///
    /// Read-only: never modifies the host or the store.
    pub async fn reconcile_with_host(&self) -> ApiResult<(Vec<String>, Vec<String>)> {
        let mut missing_in_host = Vec::new();
        let mut missing_in_store = Vec::new();
        let stored: Vec<Vm> = self.store.list().await?;

        // VMs that are in the store but not defined in libvirt. Match by the
        // stable libvirt domain name, but return DaygleVE's UUID for repair.
        let all_domains = self.list_all_domains().await?;
        let host_names: std::collections::HashSet<&str> = all_domains
            .iter()
            .map(|domain| domain.name.as_str())
            .collect();
        for vm in &stored {
            if !host_names.contains(vm.name.as_str()) {
                missing_in_host.push(vm.id.clone());
            }
        }

        // Domains defined in libvirt but not tracked in the DaygleVE store.
        let stored_names: std::collections::HashSet<&str> =
            stored.iter().map(|vm| vm.name.as_str()).collect();
        for domain in all_domains {
            if !stored_names.contains(domain.name.as_str()) {
                missing_in_store.push(domain.name);
            }
        }

        Ok((missing_in_host, missing_in_store))
    }

    /// Re-define a persisted VM missing from libvirt. This is non-destructive:
    /// it never starts the VM or changes its disks.
    pub async fn repair_missing_from_host(&self, id: &str) -> ApiResult<()> {
        let vm = self.get_stored(id).await?;
        self.require_stopped(&vm, "repairing its libvirt definition")
            .await?;
        self.define(&vm).await
    }

    /// All libvirt domains visible under `qemu:///system`, as summaries.
    async fn list_all_domains(&self) -> ApiResult<Vec<VmSummary>> {
        let out = match command::run_optional("virsh", &["-c", CONNECT, "list", "--all", "--name"])
            .await
        {
            Ok(Some(o)) => o,
            Ok(None) => {
                return Err(AppError::hypervisor(
                    "virsh is not installed; cannot reconcile VMs",
                ))
            }
            Err(e) => return Err(e),
        };

        let mut out_vec = Vec::new();
        for line in out.lines().filter(|l| !l.trim().is_empty()) {
            // We can only get the name here; the id is the domain name in
            // libvirt. We report the name as the identifier for drift.
            out_vec.push(VmSummary {
                id: line.trim().to_string(),
                name: line.trim().to_string(),
                state: VmState::Stopped,
                vcpus: 0,
                memory_mib: 0,
                // Host-only domains carry no DaygleVE template/autostart intent.
                template: false,
                autostart: false,
                tags: Vec::new(),
                pool: None,
                created_at: now_ts(),
            });
        }
        Ok(out_vec)
    }

    pub async fn power(&self, id: &str, action: VmPowerAction) -> ApiResult<VmPowerResponse> {
        let mut vm = self.get_stored(id).await?;
        // A template is a clone-only golden image and must never run. Block any
        // power action that would start or resume it; clone it instead.
        if vm.template
            && matches!(
                action,
                VmPowerAction::Start | VmPowerAction::Resume | VmPowerAction::Reboot
            )
        {
            return Err(AppError::conflict(
                "this VM is a template and cannot be powered on; clone it first",
            ));
        }
        let subcommand = match action {
            VmPowerAction::Start => "start",
            VmPowerAction::Stop => "destroy",
            VmPowerAction::Reboot => "reboot",
            VmPowerAction::Reset => "reset",
            VmPowerAction::Pause => "suspend",
            VmPowerAction::Resume => "resume",
            VmPowerAction::Shutdown => {
                // Prefer guest-agent shutdown when the agent is enabled and the VM is
                // running — the guest can then quiesce (flush writes, stop services)
                // before power-off. Fall back to the ACPI button press when the agent
                // is not connected (it may not be installed in the guest yet).
                if vm.guest_agent && self.live_state(&vm.id).await == Some(VmState::Running) {
                    match self.virsh(&["shutdown", "--mode", "agent", id]).await {
                        Ok(_) => {
                            vm.state = VmState::Transitioning;
                            vm.updated_at = Some(now_ts());
                            self.store.put(id, &vm).await?;
                            return Ok(VmPowerResponse {
                                vm,
                                guest_ips: vec![],
                            });
                        }
                        Err(e) => {
                            tracing::warn!(
                                vm_id = %id,
                                error = %e.message(),
                                "guest-agent shutdown failed; falling back to ACPI shutdown"
                            );
                        }
                    }
                }
                "shutdown"
            }
        };
        self.virsh(&[subcommand, id]).await?;

        vm.state = self.live_state(id).await.unwrap_or(vm.state);
        vm.updated_at = Some(now_ts());
        self.store.put(id, &vm).await?;
        let guest_ips = if vm.guest_agent {
            self.guest_ips(id).await.unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok(VmPowerResponse { vm, guest_ips })
    }

    /// Start every autostart-enabled VM in order, once, at host boot. VMs are
    /// started lowest `startup_order` first (unordered VMs last, then by
    /// creation time), skipping templates and any VM already running. Failures
    /// are logged and never abort the sequence — one guest that won't start must
    /// not block the rest. Intended to be spawned from startup, not awaited on
    /// the request path.
    pub async fn start_autostart_vms(&self) {
        /// Pause between starts so a burst of boots doesn't hammer the host all
        /// at once (a lightweight stand-in for per-VM start delays).
        const BETWEEN_STARTS: std::time::Duration = std::time::Duration::from_secs(2);

        let vms: Vec<Vm> = match self.store.list().await {
            Ok(vms) => vms,
            Err(e) => {
                tracing::error!(error = %e.message(), "autostart: could not read VM records");
                return;
            }
        };
        let queue = autostart_queue(vms);
        if queue.is_empty() {
            return;
        }
        tracing::info!(count = queue.len(), "autostart: starting VMs on boot");
        let mut first = true;
        for vm in queue {
            if self.live_state(&vm.id).await == Some(VmState::Running) {
                continue;
            }
            if !first {
                tokio::time::sleep(BETWEEN_STARTS).await;
            }
            first = false;
            match self.virsh(&["start", &vm.id]).await {
                Ok(_) => tracing::info!(vm_id = %vm.id, name = %vm.name, "autostart: started"),
                Err(e) => {
                    tracing::error!(vm_id = %vm.id, name = %vm.name, error = %e.message(), "autostart: failed to start")
                }
            }
        }
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

        self.mint_ticket(id, "console", ConsoleTarget::Vnc(vnc_addr))
    }

    /// Mint a serial (text) console ticket. Resolves the domain's console pty
    /// with `virsh ttyconsole`; the pty is opened only later, through the
    /// broker, when the websocket redeems the ticket.
    pub async fn serial_console(&self, id: &str) -> ApiResult<ConsoleTicket> {
        let _ = self.get_stored(id).await?;
        let pty = self
            .virsh(&["ttyconsole", id])
            .await
            .map_err(|_| AppError::conflict("start the VM to open a serial console"))?;
        let pty = pty.trim().to_string();
        // Constrain to a pty device before it is stored or opened; the broker
        // re-validates, but reject an unexpected shape early.
        crate::broker::validate_console_pty(&pty)
            .map_err(|_| AppError::hypervisor("could not resolve the VM's serial console"))?;
        self.mint_ticket(id, "serial-console", ConsoleTarget::Serial(pty))
    }

    /// Store a one-time ticket for `target` and return the console handshake
    /// pointing at `{kind}/ws`.
    fn mint_ticket(&self, id: &str, kind: &str, target: ConsoleTarget) -> ApiResult<ConsoleTicket> {
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
                    target,
                    expires_at: now + TICKET_TTL,
                },
            );
        }

        Ok(ConsoleTicket {
            websocket_path: format!("/api/v1/vms/{id}/{kind}/ws?ticket={ticket}"),
            ticket,
            expires_at: (chrono::Utc::now() + chrono::Duration::from_std(TICKET_TTL).unwrap())
                .to_rfc3339(),
        })
    }

    /// Validate and consume a console ticket, returning what to connect to.
    /// One-time: the ticket is removed on success.
    pub fn redeem_ticket(&self, vm_id: &str, ticket: &str) -> ApiResult<ConsoleTarget> {
        let mut tickets = self.tickets.write().expect("ticket lock");
        match tickets.get(ticket) {
            Some(t) if t.vm_id == vm_id && t.expires_at > Instant::now() => {
                // Consume only on a valid match, so a wrong-VM guess can't burn
                // another VM's pending ticket.
                Ok(tickets.remove(ticket).expect("ticket present").target)
            }
            _ => Err(AppError::unauthorized("invalid or expired console ticket")),
        }
    }

    /// Open a live bridge to a serial console pty (through the broker on the
    /// appliance). The pty comes from a previously-redeemed serial ticket.
    pub async fn attach_serial_console(
        &self,
        pty: &str,
    ) -> ApiResult<(command::ConsoleReadHalf, command::ConsoleWriteHalf)> {
        command::console_attach(pty).await
    }

    /// Build a `remote-viewer` connection file (`.vv`) for the VM's SPICE
    /// display. Only valid when the VM uses SPICE and is running; the port is
    /// resolved live from libvirt and the host is the configured SPICE address.
    pub async fn spice_connection(&self, id: &str) -> ApiResult<String> {
        let vm = self.get_stored(id).await?;
        if vm.display != DisplayProtocol::Spice {
            return Err(AppError::conflict(
                "this VM does not use SPICE; set its display to spice first",
            ));
        }
        let uri = self
            .virsh(&["domdisplay", "--type", "spice", id])
            .await
            .map_err(|_| AppError::conflict("start the VM to open its SPICE display"))?;
        let port = parse_spice_port(uri.trim())
            .ok_or_else(|| AppError::hypervisor("could not resolve the VM's SPICE port"))?;
        Ok(spice_connection_file(
            &vm.name,
            &self.config.spice_listen,
            port,
        ))
    }

    // --- guest agent ------------------------------------------------------

    /// Query the guest agent for status, OS info, and IP addresses. Reports the
    /// channel as not connected when the VM is stopped or the agent does not
    /// answer (e.g. qemu-guest-agent is not installed in the guest).
    pub async fn guest_agent_info(&self, id: &str) -> ApiResult<GuestAgentInfo> {
        let vm = self.get_stored(id).await?;
        let mut info = GuestAgentInfo {
            enabled: vm.guest_agent,
            connected: false,
            guest_os: None,
            guest_ips: Vec::new(),
        };
        if !vm.guest_agent {
            return Ok(info);
        }
        if self.live_state(id).await != Some(VmState::Running) {
            return Ok(info);
        }

        // guest-info answers with one `key: value` pair per line. A missing or
        // not-connected agent makes `qemu-agent-command` fail; that is the
        // "enabled but not connected" case, not an API error.
        if let Ok(out) = self
            .virsh(&["qemu-agent-command", id, "{\"execute\":\"guest-info\"}"])
            .await
        {
            info.connected = true;
            info.guest_os = parse_guest_info_field(&out, "pretty_name")
                .or_else(|| parse_guest_info_field(&out, "version"));
        }
        info.guest_ips = self.guest_ips(id).await.unwrap_or_default();
        Ok(info)
    }

    /// IP addresses reported by the guest agent for every NIC.
    async fn guest_ips(&self, id: &str) -> ApiResult<Vec<String>> {
        let out = self
            .virsh(&["domifaddr", "--source", "agent", id])
            .await
            .map_err(|_| {
                AppError::hypervisor("could not query guest addresses via the guest agent")
            })?;
        Ok(parse_domifaddr_ips(&out))
    }

    /// Ask the guest to freeze its filesystems (via the guest agent) so an
    /// on-disk snapshot is application-consistent, not just crash-consistent.
    /// Best-effort at the call sites that must proceed regardless.
    async fn fs_freeze(&self, id: &str) -> ApiResult<()> {
        self.virsh(&["domfsfreeze", id]).await.map(|_| ())
    }

    /// Counterpart to [`Self::fs_freeze`]; resumes guest filesystem writes.
    async fn fs_thaw(&self, id: &str) -> ApiResult<()> {
        self.virsh(&["domfsthaw", id]).await.map(|_| ())
    }

    // --- firewall --------------------------------------------------------

    /// Apply (or remove) the VM's host-side nftables firewall. Traffic is
    /// matched on the VM's NIC MAC addresses inside libvirt's per-bridge
    /// forward chains, so rules follow the VM across its bridges without ever
    /// touching the host's own input/output path.
    ///
    /// The ruleset is written as a batch file under the state dir and applied
    /// with `nft -f`; removal replaces the chain with an empty one rather than
    /// deleting it, which is idempotent and needs no table/chain probing.
    pub async fn apply_firewall(&self, id: &str, vm: &Vm, enabled: bool) -> ApiResult<()> {
        // vm.id feeds file paths and nft identifiers: sanitize before use.
        let safe_id = ensure_safe_id(id)?;
        let table = format!("daygleve_vm_{}", safe_id.replace('-', "_"));

        let batch = if enabled {
            nft_firewall_batch(&table, &vm.firewall, &vm.nics)?
        } else {
            // Removal: flush the chain (cheap, no dependency probing), then the
            // table is left empty and harmless until the next apply.
            format!(
                "add table {table}\nadd chain {table} forward {{ type filter hook forward priority -100; }}\nflush chain {table} forward\n"
            )
        };
        self.run_nft_batch(safe_id, &batch).await
    }

    /// Write an nft batch file under the state dir and apply it. The path is
    /// built from the sanitized id so the broker-side path check accepts it.
    async fn run_nft_batch(&self, safe_id: &str, batch: &str) -> ApiResult<()> {
        let dir = self.config.state_dir.join("firewall");
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| AppError::internal(format!("create {}: {e}", dir.display())))?;
        let path = dir.join(format!("{safe_id}.nft"));
        tokio::fs::write(&path, batch)
            .await
            .map_err(|e| AppError::internal(format!("write {}: {e}", path.display())))?;
        let path_str = path.to_string_lossy().into_owned();
        let result = command::run_ok("nft", &["-f", &path_str]).await;
        // Keep the file for auditability; the state dir is backend-private.
        result
    }

    // --- cloud-init -------------------------------------------------------

    /// Generate a cloud-init NoCloud seed ISO from the request and return its
    /// host path. The ISO carries `meta-data` (instance id + hostname) and
    /// `user-data` (default user, SSH keys, static network, optional password)
    /// and is attached to the VM as a second CD-ROM (`sdab`).
    ///
    /// Generation shells out to `genisoimage` (or `xorriso` as a fallback), the
    /// same tools the appliance uses to build its own installer ISO. The output
    /// path is derived from the sanitized VM name under the state dir, so it
    /// cannot escape the state dir and the broker path check accepts it.
    async fn create_cloud_init_iso(
        &self,
        vm_name: &str,
        req: &CloudInitRequest,
    ) -> ApiResult<String> {
        let safe_name = ensure_safe_id(vm_name)?;
        validate_cloud_init(req)?;

        let dir = self.config.state_dir.join("cloud-init");
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| AppError::internal(format!("create {}: {e}", dir.display())))?;
        let seed_dir = dir.join(safe_name);
        tokio::fs::create_dir_all(&seed_dir)
            .await
            .map_err(|e| AppError::internal(format!("create {}: {e}", seed_dir.display())))?;

        let instance_id = uuid::Uuid::new_v4().to_string();
        let meta_data = cloud_init_meta_data(req, &instance_id);
        let user_data = cloud_init_user_data(req);

        let meta_path = seed_dir.join("meta-data");
        let user_path = seed_dir.join("user-data");
        tokio::fs::write(&meta_path, meta_data)
            .await
            .map_err(|e| AppError::internal(format!("write {}: {e}", meta_path.display())))?;
        tokio::fs::write(&user_path, user_data)
            .await
            .map_err(|e| AppError::internal(format!("write {}: {e}", user_path.display())))?;

        let iso_path = dir.join(format!("{safe_name}-seed.iso"));
        let iso_str = iso_path.to_string_lossy().into_owned();
        let seed_dir_str = seed_dir.to_string_lossy().into_owned();

        // Prefer genisoimage; fall back to xorriso's mkisofs emulation.
        let made = command::run_optional(
            "genisoimage",
            &[
                "-quiet",
                "-output",
                &iso_str,
                "-volid",
                "cidata",
                "-joliet",
                "-rock",
                &seed_dir_str,
            ],
        )
        .await;
        let made = match made {
            Ok(Some(_)) => true,
            Ok(None) => command::run_ok(
                "xorriso",
                &[
                    "-as",
                    "mkisofs",
                    "-quiet",
                    "-output",
                    &iso_str,
                    "-volid",
                    "cidata",
                    "-joliet",
                    "-rock",
                    &seed_dir_str,
                ],
            )
            .await
            .is_ok(),
            Err(e) => return Err(e),
        };
        if !made {
            return Err(AppError::hypervisor(
                "could not generate the cloud-init seed ISO (install genisoimage or xorriso)",
            ));
        }
        Ok(iso_str)
    }

    // --- disk resize / hotplug --------------------------------------------

    /// Grow a disk's backing zvol and, when the VM is running, tell QEMU about
    /// the new size (`virsh blockresize`) so the guest sees it without a
    /// restart. Shrinking is rejected: it truncates data beyond the boundary.
    pub async fn resize_disk(
        &self,
        id: &str,
        index: usize,
        req: ResizeVmDiskRequest,
    ) -> ApiResult<Vm> {
        let mut vm = self.get_stored(id).await?;
        let disk = vm
            .disks
            .get(index)
            .ok_or_else(|| AppError::not_found(format!("vm {id} has no disk at index {index}")))?;
        let dataset = ensure_safe_zfs_dataset(disk.dataset.trim())?;
        if req.size_gib == 0 {
            return Err(AppError::validation("size_gib must be >= 1"));
        }
        if req.size_gib < disk.size_gib {
            return Err(AppError::validation(
                "shrinking a disk is not supported; specify a larger size_gib",
            ));
        }
        if req.size_gib == disk.size_gib {
            return Ok(vm);
        }

        let new_size = format!("{}G", req.size_gib);
        command::run_ok("zfs", &["set", &format!("volsize={new_size}"), dataset]).await?;

        // The zvol is grown; if telling the live guest fails (agent/qemu busy,
        // VM powering off), the size is still persisted — the guest picks the
        // new size up on its next start.
        let target = disk_target_name(index, disk.bus);
        if self.live_state(id).await == Some(VmState::Running) {
            if let Err(e) = self
                .virsh(&["blockresize", id, &target, &format!("{}G", req.size_gib)])
                .await
            {
                tracing::warn!(
                    vm_id = %id,
                    disk = %target,
                    error = %e.message(),
                    "guest block resize notification failed; the guest sees the new size on next start"
                );
            }
        }

        vm.disks[index].size_gib = req.size_gib;
        vm.updated_at = Some(now_ts());
        self.store.put(id, &vm).await?;
        Ok(vm)
    }

    /// Hot-attach an additional disk to a running (or stopped) VM: provision
    /// the zvol, then `virsh attach-disk`. The disk is appended to the VM's
    /// record so the next `define` renders it into the persistent XML too.
    pub async fn attach_disk(&self, id: &str, disk: VmDisk) -> ApiResult<Vm> {
        let mut vm = self.get_stored(id).await?;
        validate_disks(std::slice::from_ref(&disk))?;
        if vm.disks.len() >= 26 {
            return Err(AppError::validation(
                "the VM already has the maximum of 26 data disks",
            ));
        }
        let index = vm.disks.len();
        self.ensure_zvol(&disk).await?;

        let running = self.live_state(id).await == Some(VmState::Running);
        if running {
            let target = disk_target_name(index, disk.bus);
            let source = format!("/dev/zvol/{}", disk.dataset.trim());
            self.virsh(&["attach-disk", id, &target, &source, "--persistent"])
                .await?;
        }

        vm.disks.push(disk);
        vm.updated_at = Some(now_ts());
        self.store.put(id, &vm).await?;
        // Re-define so the persistent XML matches the record even when the VM
        // was stopped (attach-disk only runs live).
        if !running {
            self.define(&vm).await?;
        }
        Ok(vm)
    }

    /// Detach a disk by index: `virsh detach-disk` when running, then remove it
    /// from the record. The zvol and its data are intentionally left intact.
    pub async fn detach_disk(&self, id: &str, index: usize) -> ApiResult<Vm> {
        let mut vm = self.get_stored(id).await?;
        if index >= vm.disks.len() {
            return Err(AppError::not_found(format!(
                "vm {id} has no disk at index {index}"
            )));
        }
        let running = self.live_state(id).await == Some(VmState::Running);
        if running {
            let disk = vm.disks[index].clone();
            let target = disk_target_name(index, disk.bus);
            if let Err(e) = self
                .virsh(&["detach-disk", id, &target, "--persistent"])
                .await
            {
                tracing::warn!(vm_id = %id, disk = %target, error = %e.message(), "live disk detach failed");
                return Err(e);
            }
        }
        vm.disks.remove(index);
        vm.updated_at = Some(now_ts());
        self.store.put(id, &vm).await?;
        if !running {
            self.define(&vm).await?;
        }
        Ok(vm)
    }

    // --- USB / PCI device hotplug ----------------------------------------

    /// Hot-attach a host USB device to a running (or stopped) VM by
    /// vendor:product id via `virsh attach-device`. The assignment is appended
    /// to the VM's record so the next `define` renders it into the persistent
    /// XML too. USB hostdevs match by id, so a replug or host reboot keeps the
    /// passthrough intact.
    pub async fn attach_usb(&self, id: &str, req: AttachVmUsbRequest) -> ApiResult<Vm> {
        let mut vm = self.get_stored(id).await?;
        let assignment = daygleve_schema::usb::UsbAssignment {
            vendor_id: req.vendor_id,
            product_id: req.product_id,
        };
        validate_usb_assignments(std::slice::from_ref(&assignment))?;
        if vm.usb_devices.len() >= 10 {
            return Err(AppError::validation(
                "the VM already has the maximum of 10 USB passthrough devices",
            ));
        }
        if vm
            .usb_devices
            .iter()
            .any(|u| u.vendor_id == assignment.vendor_id && u.product_id == assignment.product_id)
        {
            return Err(AppError::validation(
                "that USB device is already attached to this VM",
            ));
        }

        let running = self.live_state(id).await == Some(VmState::Running);
        if running {
            self.attach_device(
                id,
                &usb_hostdev_xml(&assignment.vendor_id, &assignment.product_id)
                    .ok_or_else(|| AppError::validation("USB ids must be four hex digits"))?,
            )
            .await?;
        }

        vm.usb_devices.push(assignment);
        vm.updated_at = Some(now_ts());
        self.store.put(id, &vm).await?;
        if !running {
            self.define(&vm).await?;
        }
        Ok(vm)
    }

    /// Detach a USB passthrough device from a VM by vendor:product id:
    /// `virsh detach-device` when running, then remove it from the record.
    /// The device stays plugged into the host.
    pub async fn detach_usb(&self, id: &str, vendor_id: &str, product_id: &str) -> ApiResult<Vm> {
        let mut vm = self.get_stored(id).await?;
        let position = vm
            .usb_devices
            .iter()
            .position(|u| u.vendor_id == vendor_id && u.product_id == product_id)
            .ok_or_else(|| {
                AppError::not_found(format!(
                    "vm {id} has no USB device {vendor_id}:{product_id} attached"
                ))
            })?;
        let running = self.live_state(id).await == Some(VmState::Running);
        if running {
            let xml = usb_hostdev_xml(vendor_id, product_id)
                .ok_or_else(|| AppError::validation("USB ids must be four hex digits"))?;
            self.detach_device(id, &xml).await?;
        }
        vm.usb_devices.remove(position);
        vm.updated_at = Some(now_ts());
        self.store.put(id, &vm).await?;
        if !running {
            self.define(&vm).await?;
        }
        Ok(vm)
    }

    /// Hot-attach a host PCI function to a running (or stopped) VM via
    /// `virsh attach-device`. The assignment is appended to the VM's record so
    /// the next `define` renders it into the persistent XML too.
    pub async fn attach_pci(&self, id: &str, req: AttachVmPciRequest) -> ApiResult<Vm> {
        let mut vm = self.get_stored(id).await?;
        let assignment = daygleve_schema::pci::PciAssignment {
            pci_address: req.pci_address,
        };
        validate_pci_assignments(std::slice::from_ref(&assignment))?;
        if vm
            .pci_devices
            .iter()
            .any(|p| p.pci_address.eq_ignore_ascii_case(&assignment.pci_address))
        {
            return Err(AppError::validation(
                "that PCI device is already attached to this VM",
            ));
        }

        let running = self.live_state(id).await == Some(VmState::Running);
        if running {
            self.attach_device(
                id,
                &pci_hostdev_xml(&assignment.pci_address)
                    .ok_or_else(|| AppError::validation("invalid PCI address"))?,
            )
            .await?;
        }

        vm.pci_devices.push(assignment);
        vm.updated_at = Some(now_ts());
        self.store.put(id, &vm).await?;
        if !running {
            self.define(&vm).await?;
        }
        Ok(vm)
    }

    /// Detach a PCI passthrough device from a VM by address: `virsh
    /// detach-device` when running, then remove it from the record.
    pub async fn detach_pci(&self, id: &str, pci_address: &str) -> ApiResult<Vm> {
        let mut vm = self.get_stored(id).await?;
        let position = vm
            .pci_devices
            .iter()
            .position(|p| p.pci_address.eq_ignore_ascii_case(pci_address))
            .ok_or_else(|| {
                AppError::not_found(format!("vm {id} has no PCI device {pci_address} attached"))
            })?;
        let running = self.live_state(id).await == Some(VmState::Running);
        if running {
            let xml = pci_hostdev_xml(pci_address)
                .ok_or_else(|| AppError::validation("invalid PCI address"))?;
            self.detach_device(id, &xml).await?;
        }
        vm.pci_devices.remove(position);
        vm.updated_at = Some(now_ts());
        self.store.put(id, &vm).await?;
        if !running {
            self.define(&vm).await?;
        }
        Ok(vm)
    }

    // --- snapshots -------------------------------------------------------

    /// List the VM's snapshots, one entry per snapshot name present on *every*
    /// one of the VM's disks. `used_bytes` is summed over those per-disk
    /// snapshots. Names that cover only some disks (e.g. a partial cross-pool
    /// create) are omitted, so the list stays consistent with rollback/delete —
    /// which operate on all disks — and with the summed-bytes semantics.
    pub async fn list_snapshots(&self, id: &str) -> ApiResult<Vec<VmSnapshot>> {
        let vm = self.get_stored(id).await?;
        let datasets = snapshot_datasets(&vm)?;
        let disk_count = datasets.len();
        // Each entry pairs the accumulating snapshot with how many disks carry it.
        let mut by_name: BTreeMap<String, (VmSnapshot, usize)> = BTreeMap::new();
        for &dataset in &datasets {
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
                // `-p` always emits numeric used/creation; a row that doesn't
                // parse is malformed output, so skip it rather than fabricate a
                // 0-byte / epoch-0 entry that would read as a real snapshot.
                let (Some(used), Some(creation)) = (
                    cols.next().and_then(|s| s.parse::<u64>().ok()),
                    cols.next().and_then(|s| s.parse::<i64>().ok()),
                ) else {
                    continue;
                };
                let desc = cols.next().unwrap_or("-");
                let Some((_, tag)) = full.split_once('@') else {
                    continue;
                };
                // Hide internal clone-base snapshots from the user-facing list.
                if tag.starts_with(CLONE_SNAPSHOT_PREFIX) {
                    continue;
                }
                let (entry, count) = by_name.entry(tag.to_string()).or_insert_with(|| {
                    (
                        VmSnapshot {
                            name: tag.to_string(),
                            used_bytes: 0,
                            description: None,
                            created_at: ts_from_unix(creation),
                            snapshot_type: VmSnapshotType::Disk,
                        },
                        0,
                    )
                });
                entry.used_bytes = entry.used_bytes.saturating_add(used);
                *count += 1;
                // Take the description from whichever disk carries one, rather than
                // letting an unset (`-`) first disk mask a later disk's value.
                if entry.description.is_none() && desc != "-" && !desc.is_empty() {
                    entry.description = Some(desc.to_string());
                }
            }
        }
        let mut snaps: Vec<VmSnapshot> = by_name
            .into_values()
            .filter(|(_, count)| disk_count > 0 && *count == disk_count)
            .map(|(snap, _)| snap)
            .collect();
        // RAM-state snapshots live as `virsh save` images in the backend's own
        // state dir, not as ZFS snapshots; list them alongside by name.
        if let Ok(mut entries) =
            tokio::fs::read_dir(self.config.state_dir.join("ram-snapshots")).await
        {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("save") {
                    continue;
                }
                let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                if ensure_safe_snapshot(stem).is_err() {
                    continue;
                }
                let meta = entry.metadata().await.ok();
                let created = meta
                    .as_ref()
                    .and_then(|m| m.created().ok())
                    .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339())
                    .unwrap_or_else(now_ts);
                let description = tokio::fs::read_to_string(path.with_extension("json"))
                    .await
                    .ok()
                    .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
                    .and_then(|v| {
                        v.get("description")
                            .and_then(|d| d.as_str().map(str::to_string))
                    });
                snaps.push(VmSnapshot {
                    name: stem.to_string(),
                    used_bytes: meta.as_ref().map(|m| m.len()).unwrap_or(0),
                    description,
                    created_at: created,
                    snapshot_type: VmSnapshotType::Ram,
                });
            }
        }
        snaps.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(snaps)
    }

    /// Snapshot the VM under a single name.
    ///
    /// `disk` (the default) captures every backing ZFS dataset — works while the
    /// VM is running (crash-consistent), and when the guest agent is connected
    /// the guest's filesystems are frozen around the capture so the result is
    /// application-consistent. `ram` additionally saves the guest's memory via
    /// `virsh save` (running VMs only); restoring it resumes the VM from exactly
    /// the captured point. Rollback is the guarded operation, not capture.
    pub async fn create_snapshot(
        &self,
        id: &str,
        req: CreateVmSnapshotRequest,
    ) -> ApiResult<VmSnapshot> {
        match req.snapshot_type {
            VmSnapshotType::Ram => self.create_ram_snapshot(id, req).await,
            VmSnapshotType::Disk => self.create_disk_snapshot(id, req).await,
        }
    }

    /// The `disk` capture path: a ZFS snapshot of every backing dataset.
    async fn create_disk_snapshot(
        &self,
        id: &str,
        req: CreateVmSnapshotRequest,
    ) -> ApiResult<VmSnapshot> {
        let vm = self.get_stored(id).await?;
        // ensure_safe_snapshot also rejects the reserved clone-base prefix, so a
        // user snapshot can't vanish from listing or collide with a clone base.
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

        // With the guest agent enabled and the VM running, freeze the guest's
        // filesystems around the capture. Freeze is best-effort: an agent that
        // isn't installed (yet) must not block a crash-consistent snapshot, and
        // a failed thaw must be retried rather than fail the already-taken
        // snapshot, so it is logged and surfaced via tracing only.
        let frozen = vm.guest_agent && self.live_state(id).await == Some(VmState::Running);
        if frozen {
            if let Err(e) = self.fs_freeze(id).await {
                tracing::warn!(vm_id = %id, error = %e.message(), "guest fs-freeze failed; continuing crash-consistent");
            }
        }

        // One `zfs snapshot` call over all disks captures them together, and is
        // atomic when the disks share a pool (the common single-node case). Across
        // pools ZFS still creates the whole set but not atomically, so on any
        // failure we best-effort destroy whatever got created to avoid leaving a
        // half-formed snapshot behind.
        let targets: Vec<String> = datasets.iter().map(|d| format!("{d}@{tag}")).collect();
        let mut args: Vec<&str> = vec!["snapshot"];
        args.extend(targets.iter().map(String::as_str));
        let capture = command::run_ok("zfs", &args).await;

        if frozen {
            if let Err(e) = self.fs_thaw(id).await {
                tracing::error!(vm_id = %id, error = %e.message(), "guest fs-thaw failed; guest filesystems may remain frozen");
            }
        }

        if let Err(e) = capture {
            for target in &targets {
                let _ = command::run_ok("zfs", &["destroy", target]).await;
            }
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
            // The description is read back from tab-delimited `zfs list -H` output,
            // so collapse any control whitespace (tabs, newlines) to spaces before
            // storing it, or a value with a tab/newline would corrupt that parse.
            let sanitized: String = desc
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect();
            let prop = format!("daygleve:description={}", sanitized.trim());
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

    /// The `ram` capture path: `virsh save` writes the guest's memory and device
    /// state to a host file, leaving the domain undefined-but-restartable from
    /// that file. The capture is application-consistent by construction (the
    /// guest CPUs are paused mid-flight, disk writes in flight are settled).
    async fn create_ram_snapshot(
        &self,
        id: &str,
        req: CreateVmSnapshotRequest,
    ) -> ApiResult<VmSnapshot> {
        let vm = self.get_stored(id).await?;
        let tag = ensure_safe_snapshot(&req.name)?;
        if self.live_state(id).await != Some(VmState::Running) {
            return Err(AppError::conflict(
                "a RAM-state snapshot requires the VM to be running",
            ));
        }
        if self.list_snapshots(id).await?.iter().any(|s| s.name == tag) {
            return Err(AppError::conflict(format!(
                "a snapshot named {tag:?} already exists"
            )));
        }

        let path = self.ram_snapshot_path(tag)?;
        let path_str = path.to_string_lossy().into_owned();
        if let Err(e) = self.virsh(&["save", id, &path_str]).await {
            // A partially written save image is useless; drop it.
            let _ = tokio::fs::remove_file(&path).await;
            return Err(e);
        }

        if let Some(desc) = req.description.as_deref().filter(|d| !d.trim().is_empty()) {
            // Best-effort sidecar metadata; a failed write must not fail the
            // already-captured snapshot.
            let _ = tokio::fs::write(
                path.with_extension("json"),
                serde_json::json!({
                    "description": desc.trim(),
                    "created_at": now_ts(),
                    "vm_id": vm.id,
                })
                .to_string(),
            )
            .await;
        }

        // Save leaves the domain "shut off" from libvirt's perspective; report
        // that so the UI shows the VM as stopped-with-saved-state.
        let mut stored = self.get_stored(id).await?;
        stored.state = self.live_state(id).await.unwrap_or(VmState::Stopped);
        stored.updated_at = Some(now_ts());
        self.store.put(id, &stored).await?;

        let meta = tokio::fs::metadata(&path).await.ok();
        Ok(VmSnapshot {
            name: tag.to_string(),
            used_bytes: meta.as_ref().map(|m| m.len()).unwrap_or(0),
            description: req.description,
            created_at: now_ts(),
            snapshot_type: VmSnapshotType::Ram,
        })
    }

    /// Restore a RAM-state snapshot: resume the VM from a `virsh save` image.
    /// Restoring is destructive of the VM's current running state by design.
    pub async fn restore_ram_snapshot(&self, id: &str, name: &str) -> ApiResult<Vm> {
        let mut vm = self.get_stored(id).await?;
        let tag = ensure_safe_snapshot(name)?;
        let path = self.ram_snapshot_path(tag)?;
        if !path.exists() {
            return Err(AppError::not_found(format!(
                "no RAM-state snapshot named {tag:?}"
            )));
        }
        let path_str = path.to_string_lossy().into_owned();
        self.virsh(&["restore", &path_str]).await?;

        vm.state = self.live_state(id).await.unwrap_or(VmState::Running);
        vm.updated_at = Some(now_ts());
        self.store.put(id, &vm).await?;
        Ok(vm)
    }

    /// Host path of a RAM-state snapshot's save image. Names are validated
    /// through [`ensure_safe_snapshot`] before reaching here, and the parent
    /// directory is the backend's own state dir, so the path cannot escape.
    fn ram_snapshot_path(&self, tag: &str) -> ApiResult<std::path::PathBuf> {
        ensure_safe_id(tag)?;
        Ok(self
            .config
            .state_dir
            .join("ram-snapshots")
            .join(format!("{tag}.save")))
    }

    /// Roll every disk back to the named snapshot. Destructive of any newer
    /// snapshots (`zfs rollback -r`) and only allowed while the VM is stopped.
    pub async fn rollback_snapshot(&self, id: &str, name: &str) -> ApiResult<()> {
        let vm = self.get_stored(id).await?;
        let tag = ensure_safe_snapshot(name)?;
        self.require_stopped(&vm, "rolling back a snapshot").await?;
        // Require the snapshot on every disk before touching any of them, so an
        // incomplete snapshot yields a clean 404 rather than a mid-loop 502.
        let datasets = snapshot_datasets(&vm)?;
        if !self.snapshot_on_all_disks(&datasets, tag).await? {
            return Err(AppError::not_found(format!("no snapshot named {tag:?}")));
        }
        for dataset in &datasets {
            let target = format!("{dataset}@{tag}");
            command::run_ok("zfs", &["rollback", "-r", &target]).await?;
        }
        Ok(())
    }

    /// Delete the named snapshot. For a `disk` snapshot this destroys the
    /// `dataset@tag` ZFS snapshot on every disk; for a `ram` snapshot it removes
    /// the `virsh save` image (and sidecar metadata) from the host.
    pub async fn delete_snapshot(&self, id: &str, name: &str) -> ApiResult<()> {
        let vm = self.get_stored(id).await?;
        let tag = ensure_safe_snapshot(name)?;

        let ram_path = self.ram_snapshot_path(tag)?;
        if ram_path.exists() {
            tokio::fs::remove_file(&ram_path)
                .await
                .map_err(|e| AppError::internal(format!("remove {}: {e}", ram_path.display())))?;
            let _ = tokio::fs::remove_file(ram_path.with_extension("json")).await;
            return Ok(());
        }

        // As with rollback, verify the snapshot on every disk up front so a
        // partial snapshot is a 404 rather than a half-completed destroy.
        let datasets = snapshot_datasets(&vm)?;
        if !self.snapshot_on_all_disks(&datasets, tag).await? {
            return Err(AppError::not_found(format!("no snapshot named {tag:?}")));
        }
        for dataset in &datasets {
            let target = format!("{dataset}@{tag}");
            command::run_ok("zfs", &["destroy", &target]).await?;
        }
        Ok(())
    }

    /// Whether `dataset@tag` exists on every one of the given datasets, so a
    /// caller can reject an incomplete snapshot before a destructive loop.
    /// Returns `Ok(false)` when at least one disk lacks the snapshot (a clean
    /// 404), but a missing `zfs` binary is an operational error on these
    /// destructive endpoints and surfaces as a hypervisor error (502) rather than
    /// masquerading as "not found".
    async fn snapshot_on_all_disks(&self, datasets: &[&str], tag: &str) -> ApiResult<bool> {
        if datasets.is_empty() {
            return Ok(false);
        }
        for dataset in datasets {
            let target = format!("{dataset}@{tag}");
            match command::run_optional(
                "zfs",
                &["list", "-H", "-o", "name", "-t", "snapshot", &target],
            )
            .await
            {
                Ok(Some(o)) if !o.trim().is_empty() => {}
                // Empty output, or a "does not exist" error: the snapshot is
                // absent on this dataset, so it isn't complete → 404.
                Ok(Some(_)) => return Ok(false),
                Err(e) if is_missing_dataset(&e) => return Ok(false),
                // zfs isn't installed: a host-configuration problem, not a 404.
                Ok(None) => {
                    return Err(AppError::hypervisor(
                        "zfs is not installed; cannot manage snapshots",
                    ))
                }
                // A permission/transient failure must not masquerade as 404.
                Err(e) => return Err(e),
            }
        }
        Ok(true)
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
                        "cannot confirm the VM is stopped: the libvirt connection is unavailable \
                         (check libvirtd, the qemu:///system socket and permissions); try again",
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Write a device XML fragment to the state dir and live-attach it to the
    /// running domain (`virsh attach-device`). Not `--persistent`: the stored
    /// record is the source of truth and is re-defined on the next stop/start.
    async fn attach_device(&self, id: &str, device_xml: &str) -> ApiResult<()> {
        self.device_command(id, device_xml, "attach-device").await
    }

    /// Live-detach a device by its XML fragment (`virsh detach-device`).
    async fn detach_device(&self, id: &str, device_xml: &str) -> ApiResult<()> {
        self.device_command(id, device_xml, "detach-device").await
    }

    /// Shared plumbing for `attach-device`/`detach-device`: stage the device
    /// XML under the state dir the broker trusts, run virsh, clean up.
    async fn device_command(&self, id: &str, device_xml: &str, subcommand: &str) -> ApiResult<()> {
        crate::services::ensure_safe_id(id)?;
        let dir = self.config.state_dir.join("tmp");
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| AppError::internal(format!("create {}: {e}", dir.display())))?;
        let path = dir.join(format!(
            "{}-{subcommand}.xml",
            uuid::Uuid::new_v4().simple()
        ));
        tokio::fs::write(&path, device_xml)
            .await
            .map_err(|e| AppError::internal(format!("write {}: {e}", path.display())))?;
        let path_str = path.to_string_lossy().into_owned();
        let result = self.virsh(&[subcommand, id, &path_str]).await;
        let _ = tokio::fs::remove_file(&path).await;
        result.map(|_| ())
    }

    /// Write the domain XML and (re)define it in libvirt.
    async fn define(&self, vm: &Vm) -> ApiResult<()> {
        // vm.id is a backend-minted UUID, but validate before it reaches a path.
        crate::services::ensure_safe_id(&vm.id)?;
        let xml = domain_xml(vm, &self.config.spice_listen);
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
    async fn ensure_zvol(&self, disk: &VmDisk) -> ApiResult<bool> {
        let dataset = ensure_safe_zfs_dataset(disk.dataset.trim())?;
        if disk.size_gib == 0 {
            return Err(AppError::validation("disk size_gib must be >= 1"));
        }
        // Reuse an existing dataset; otherwise create it. Distinguish "zfs not
        // installed" (fail fast — we must never define a domain pointing at a
        // zvol that was never provisioned) from "dataset does not exist yet".
        match command::run_optional("zfs", &["list", "-H", "-o", "name", dataset]).await {
            Ok(Some(_)) => return Ok(false),
            Ok(None) => {
                return Err(AppError::hypervisor(
                    "zfs is not installed; cannot provision the VM disk",
                ))
            }
            Err(e) if is_missing_dataset(&e) => {}
            Err(e) => return Err(e),
        }
        let size = format!("{}G", disk.size_gib);
        command::run_ok("zfs", &["create", "-V", &size, dataset]).await?;
        Ok(true)
    }

    async fn cleanup_created_zvols(&self, datasets: &[String]) {
        for dataset in datasets {
            let _ = command::run_ok("zfs", &["destroy", "-r", dataset]).await;
        }
    }

    /// Import an uploaded disk image (already resolved to its absolute host path
    /// by the library service) into a brand-new ZFS zvol.
    ///
    /// The image's virtual size is detected with `qemu-img info` and the zvol is
    /// provisioned to hold it (or to the larger caller-requested size), then the
    /// image is written into the zvol block device with `qemu-img convert -O raw`.
    /// The dataset must not already exist, so an import never overwrites a disk in
    /// use; a conversion failure destroys the just-created zvol so no empty
    /// half-written volume is left behind.
    pub async fn import_disk_image(
        &self,
        source_path: &str,
        dataset: &str,
        size_gib: Option<u64>,
    ) -> ApiResult<VmDisk> {
        let dataset = ensure_safe_zfs_dataset(dataset.trim())?;

        // Refuse to touch an existing dataset: import only ever creates a fresh
        // zvol. Distinguish "zfs missing" (fail fast) from "does not exist yet".
        match command::run_optional("zfs", &["list", "-H", "-o", "name", dataset]).await {
            Ok(Some(_)) => {
                return Err(AppError::validation(
                    "target dataset already exists; choose a new dataset for the import",
                ))
            }
            Ok(None) => {
                return Err(AppError::hypervisor(
                    "zfs is not installed; cannot import the disk image",
                ))
            }
            Err(e) if is_missing_dataset(&e) => {}
            Err(e) => return Err(e),
        }

        // Detect the image's virtual size so the zvol is large enough to hold it.
        let info = command::run("qemu-img", &["info", "--output=json", source_path]).await?;
        let virtual_bytes = parse_qemu_img_virtual_size(&info)?;
        let detected_gib = virtual_bytes.div_ceil(1024 * 1024 * 1024).max(1);
        let target_gib = match size_gib {
            Some(0) => return Err(AppError::validation("size_gib must be >= 1")),
            Some(g) if g < detected_gib => {
                return Err(AppError::validation(format!(
                    "size_gib ({g}) is smaller than the image's virtual size ({detected_gib} GiB)"
                )))
            }
            Some(g) => g,
            None => detected_gib,
        };

        // Provision the zvol, then stream the image into its block device.
        let size = format!("{target_gib}G");
        command::run_ok("zfs", &["create", "-V", &size, dataset]).await?;

        let device = format!("/dev/zvol/{dataset}");
        if let Err(e) =
            command::run_ok("qemu-img", &["convert", "-O", "raw", source_path, &device]).await
        {
            // Roll back the empty zvol so a failed conversion leaves nothing behind.
            let _ = command::run_ok("zfs", &["destroy", "-r", dataset]).await;
            return Err(e);
        }

        Ok(VmDisk {
            dataset: dataset.to_string(),
            size_gib: target_gib,
            bus: DiskBus::Virtio,
        })
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

fn validate_vm_request(req: &CreateVmRequest) -> ApiResult<()> {
    if req.name.trim().is_empty() {
        return Err(AppError::validation("name must not be empty"));
    }
    ensure_safe_id(&req.name)?;
    if req.vcpus == 0 {
        return Err(AppError::validation("vcpus must be >= 1"));
    }
    if req.memory_mib == 0 {
        return Err(AppError::validation("memory_mib must be >= 1"));
    }
    validate_disks(&req.disks)?;
    validate_nics(&req.nics)
}

fn validate_disks(disks: &[VmDisk]) -> ApiResult<()> {
    for disk in disks {
        ensure_safe_zfs_dataset(disk.dataset.trim())?;
        if disk.size_gib == 0 {
            return Err(AppError::validation("disk size_gib must be >= 1"));
        }
    }
    Ok(())
}

fn validate_nics(nics: &[VmNic]) -> ApiResult<()> {
    for nic in nics {
        ensure_safe_id(&nic.bridge)?;
        if let Some(vlan) = nic.vlan {
            if !(1..=4094).contains(&vlan) {
                return Err(AppError::validation("NIC VLAN must be in 1..=4094"));
            }
        }
        if let Some(mac) = nic.mac.as_deref() {
            ensure_safe_mac(mac)?;
        }
    }
    Ok(())
}

fn normalize_nics(nics: Vec<VmNic>) -> ApiResult<Vec<VmNic>> {
    validate_nics(&nics)?;
    let mut seen = std::collections::HashSet::new();
    nics.into_iter()
        .map(|mut nic| {
            nic.mac = Some(nic.mac.unwrap_or_else(generate_mac));
            if !seen.insert(nic.mac.clone().unwrap_or_default().to_ascii_lowercase()) {
                return Err(AppError::conflict("duplicate VM NIC MAC address"));
            }
            Ok(nic)
        })
        .collect()
}

fn validate_gpu_assignments(gpus: &[daygleve_schema::gpu::GpuAssignment]) -> ApiResult<()> {
    let mut seen = std::collections::HashSet::new();
    for gpu in gpus {
        ensure_safe_pci_address(&gpu.pci_address)?;
        if !seen.insert(gpu.pci_address.to_ascii_lowercase()) {
            return Err(AppError::conflict("duplicate GPU assignment"));
        }
    }
    Ok(())
}

/// The ordered set of VMs to bring up at host boot: autostart-enabled,
/// non-template VMs, lowest `startup_order` first (unordered last), stable by
/// creation time.
fn autostart_queue(vms: Vec<Vm>) -> Vec<Vm> {
    let mut queue: Vec<Vm> = vms
        .into_iter()
        .filter(|vm| vm.autostart && !vm.template)
        .collect();
    queue.sort_by(|a, b| {
        a.startup_order
            .unwrap_or(u32::MAX)
            .cmp(&b.startup_order.unwrap_or(u32::MAX))
            .then_with(|| a.created_at.cmp(&b.created_at))
    });
    queue
}

fn summary_of(vm: &Vm) -> VmSummary {
    VmSummary {
        id: vm.id.clone(),
        name: vm.name.clone(),
        state: vm.state,
        vcpus: vm.vcpus,
        memory_mib: vm.memory_mib,
        template: vm.template,
        autostart: vm.autostart,
        tags: vm.tags.clone(),
        pool: vm.pool.clone(),
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
/// timestamp. The caller only reaches here with a `creation` that already parsed
/// as an `i64` (rows whose columns don't parse are skipped), so the current-time
/// fallback covers just the theoretical case of a `secs` outside the range
/// `DateTime` can represent.
pub(crate) fn ts_from_unix(secs: i64) -> daygleve_schema::common::Timestamp {
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
    ensure_safe_zfs_dataset(dataset)
}

/// Validate a *user-supplied* ZFS snapshot tag and return it, so callers build
/// the `dataset@tag` from the sanitizer's output (path/flag-injection barrier).
/// Accepts the ZFS-safe set — letters, digits, and the punctuation `_`, `-`,
/// `.`, `:` (no spaces) — rejects a leading `-` that a host CLI could read as a
/// flag, and rejects the reserved clone-base prefix so no user snapshot
/// entrypoint (create/rollback/delete) can target an internal clone base.
/// Internal clone bases build their tag directly and never pass through here.
pub(crate) fn ensure_safe_snapshot(name: &str) -> ApiResult<&str> {
    if name.starts_with(CLONE_SNAPSHOT_PREFIX) {
        return Err(AppError::validation(format!(
            "snapshot name must not start with the reserved prefix {CLONE_SNAPSHOT_PREFIX:?}"
        )));
    }
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

/// Extract the `virtual-size` (bytes) from `qemu-img info --output=json` output.
/// This is the logical capacity the image presents, which the imported zvol must
/// be at least as large as.
fn parse_qemu_img_virtual_size(json: &str) -> ApiResult<u64> {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .as_ref()
        .and_then(|v| v.get("virtual-size"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| AppError::hypervisor("could not determine the disk image's virtual size"))
}

/// True when a `zfs` error indicates the target dataset simply does not exist,
/// as opposed to a permission or transient failure we must not hide.
pub(crate) fn is_missing_dataset(e: &AppError) -> bool {
    let m = e.message().to_ascii_lowercase();
    m.contains("does not exist") || m.contains("dataset does not exist")
}

/// True when a `zfs snapshot` error indicates the snapshot already exists, so a
/// racing create can be reported as a 409 instead of a 502.
pub(crate) fn is_already_exists(e: &AppError) -> bool {
    e.message().to_ascii_lowercase().contains("already exists")
}

/// A fresh locally-administered unicast MAC in QEMU's `52:54:00` OUI, with three
/// random host bytes from a v4 UUID. Used to give a cloned VM its own MACs.
fn generate_mac() -> String {
    let b = uuid::Uuid::new_v4().into_bytes();
    format!("52:54:00:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2])
}

/// Parse `virsh vncdisplay` output (`host:N` or `:N`) to a `host:port` socket.
fn parse_vnc_display(display: &str) -> Option<String> {
    let (host, disp) = display.rsplit_once(':')?;
    let n: u16 = disp.trim().parse().ok()?;
    let host = if host.is_empty() { "127.0.0.1" } else { host };
    Some(format!("{host}:{}", 5900 + n))
}

/// Extract the SPICE port from `virsh domdisplay --type spice` output, which is
/// a URI like `spice://127.0.0.1:5901` or `spice://127.0.0.1?port=5901`.
fn parse_spice_port(uri: &str) -> Option<u16> {
    // Prefer an explicit `port` query parameter (matched as a whole key, so
    // `tls-port=` is never mistaken for it), else the `:port` after the host.
    if let Some(query) = uri.split('?').nth(1) {
        for pair in query.split('&') {
            if let Some(value) = pair.strip_prefix("port=") {
                if let Ok(port) = value.parse::<u16>() {
                    return Some(port);
                }
            }
        }
    }
    let after_scheme = uri.strip_prefix("spice://").unwrap_or(uri);
    let host_port = after_scheme
        .split(['/', '?'])
        .next()
        .unwrap_or(after_scheme);
    let (_, port) = host_port.rsplit_once(':')?;
    port.parse::<u16>().ok()
}

/// A `remote-viewer` connection file (`.vv`, an INI document) for a SPICE
/// display. `delete-this-file=1` asks the viewer to remove the downloaded file
/// after connecting, since it names the reachable host and port.
fn spice_connection_file(vm_name: &str, host: &str, port: u16) -> String {
    // Strip any characters that could break the INI line; names are host-safe
    // already, but the title is cosmetic so keep it conservative.
    let title: String = vm_name
        .chars()
        .filter(|c| !c.is_control() && *c != '\n')
        .collect();
    format!(
        "[virt-viewer]\n\
         type=spice\n\
         host={host}\n\
         port={port}\n\
         title={title} - SPICE\n\
         delete-this-file=1\n\
         toggle-fullscreen=shift+f11\n\
         release-cursor=shift+f12\n"
    )
}

/// Guest-visible target name for disk `index` on `bus`, matching what
/// [`domain_xml`] renders for the same position (single-letter scheme) plus
/// the two-letter CD-ROMs at the end of the SATA alphabet.
fn disk_target_name(index: usize, bus: DiskBus) -> String {
    disk_target(bus, index).0
}

/// Extract one `key: value` field from `virsh qemu-agent-command` guest-info
/// output. Values may carry a trailing comma; both are trimmed.
fn parse_guest_info_field(output: &str, key: &str) -> Option<String> {
    for line in output.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once(':') {
            if k.trim() == key {
                let value = v.trim().trim_end_matches(',').trim();
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

/// Pull the IPv4/IPv6 addresses out of `virsh domifaddr --source agent` output.
/// A row looks like: `lo    00:00:00:00:00:00    ipv4    127.0.0.1/8`.
fn parse_domifaddr_ips(output: &str) -> Vec<String> {
    let mut ips = Vec::new();
    for line in output.lines().skip(2) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 || cols[2] != "ipv4" && cols[2] != "ipv6" {
            continue;
        }
        let addr = cols[3].split('/').next().unwrap_or_default();
        if !addr.is_empty() && !ips.contains(&addr.to_string()) {
            ips.push(addr.to_string());
        }
    }
    ips
}

/// Validate a firewall config before its values reach nftables: MACs already
/// come from validated NICs, but CIDRs and the enabled/rule invariants must be
/// checked here.
fn validate_firewall(fw: &VmFirewall) -> ApiResult<()> {
    for rule in &fw.rules {
        match rule.action {
            VmFirewallAction::AcceptAll | VmFirewallAction::DropAll => {
                if rule.cidr.is_some() {
                    return Err(AppError::validation(
                        "accept_all/drop_all rules must not carry a cidr",
                    ));
                }
            }
            VmFirewallAction::Accept | VmFirewallAction::Drop => {
                let cidr = rule
                    .cidr
                    .as_deref()
                    .ok_or_else(|| AppError::validation("accept/drop rules require a cidr"))?;
                ensure_safe_cidr(cidr, "firewall rule cidr")?;
            }
        }
        if let Some(cidr) = rule.cidr.as_deref() {
            ensure_safe_cidr(cidr, "firewall rule cidr")?;
        }
    }
    Ok(())
}

/// Render the nftables batch for one VM. The chain hooks `forward` at a lower
/// priority than the base chain, matching on the guest's NIC MAC addresses via
/// `ether saddr`/`ether daddr`, so host-local traffic is never filtered and the
/// rules survive bridge renames. Return traffic for established connections is
/// accepted first; then rules apply in order; unmatched traffic is dropped.
/// `table` is the table *name* (no family); the `inet` family is used so the
/// same rules cover IPv4 and IPv6.
fn nft_firewall_batch(table: &str, fw: &VmFirewall, nics: &[VmNic]) -> ApiResult<String> {
    let macs: Vec<&str> = nics
        .iter()
        .filter_map(|n| n.mac.as_deref())
        .filter(|m| ensure_safe_mac(m).is_ok())
        .collect();
    if macs.is_empty() {
        return Err(AppError::validation(
            "firewall requires at least one NIC with a valid MAC address",
        ));
    }
    // The chain name derives from the table name, which must already be a
    // single token (built from the sanitized VM id upstream).
    if table.chars().any(|c| c.is_whitespace()) {
        return Err(AppError::internal(
            "firewall table name must be a single token",
        ));
    }
    let chain = format!("vm_{table}_rules");

    let mut b = String::new();
    b.push_str(&format!("add table inet {table}\n"));
    b.push_str(&format!(
        "add chain inet {table} forward {{ type filter hook forward priority -100; }}\n"
    ));
    b.push_str(&format!("flush chain inet {table} forward\n"));

    let mut mac_match = String::new();
    for (i, mac) in macs.iter().enumerate() {
        if i > 0 {
            mac_match.push_str(" || ");
        }
        mac_match.push_str(&format!("ether saddr {mac} || ether daddr {mac}"));
    }
    // Established/related return traffic first, then everything this VM's MACs
    // own falls through to the user rules; anything else in this chain is left
    // to later hooks (the chain only ever judges the VM's own traffic).
    b.push_str(&format!(
        "add rule inet {table} forward ct state established,related accept\n"
    ));
    b.push_str(&format!(
        "add rule inet {table} forward {mac_match} jump {chain}\n"
    ));
    b.push_str(&format!("add rule inet {table} forward {mac_match} drop\n"));

    b.push_str(&format!("add chain inet {table} {chain}\n"));
    for rule in &fw.rules {
        let verdict = match rule.action {
            VmFirewallAction::Accept | VmFirewallAction::AcceptAll => "accept",
            VmFirewallAction::Drop | VmFirewallAction::DropAll => "drop",
        };
        let dir = match rule.direction {
            // Outbound from the guest: our MAC is the source.
            VmFirewallDirection::Out => "ether saddr",
            // Inbound to the guest: our MAC is the destination.
            VmFirewallDirection::In => "ether daddr",
        };
        // Inbound rules match on the packet's source address; outbound rules
        // match on its destination. `*_all` rules carry no CIDR at all.
        let cidr_part = rule
            .cidr
            .as_deref()
            .map(|c| match rule.direction {
                VmFirewallDirection::In => format!("ip saddr {c}"),
                VmFirewallDirection::Out => format!("ip daddr {c}"),
            })
            .unwrap_or_default();
        let mut parts: Vec<&str> = vec![dir];
        if !cidr_part.is_empty() {
            parts.push(cidr_part.trim());
        }
        parts.push(verdict);
        b.push_str(&format!(
            "add rule inet {table} {chain} {}\n",
            parts.join(" ")
        ));
    }
    Ok(b)
}

/// Validate cloud-init inputs before they are rendered into the seed files:
/// the values end up in YAML read by the guest, so no control characters, and
/// every CIDR/address is checked host-side.
fn validate_cloud_init(req: &CloudInitRequest) -> ApiResult<()> {
    if let Some(hostname) = req.hostname.as_deref() {
        ensure_safe_id(hostname)?;
    }
    if let Some(user) = req.default_user.as_deref() {
        ensure_safe_id(user)?;
    }
    for key in &req.ssh_keys {
        if key.is_empty() || key.len() > 4096 || key.chars().any(|c| c.is_control()) {
            return Err(AppError::validation(
                "ssh key must be a single-line OpenSSH public key",
            ));
        }
    }
    if let Some(net) = req.network.as_ref() {
        ensure_safe_cidr(&net.address, "cloud-init network address")?;
        if let Some(gw) = net.gateway.as_deref() {
            // The gateway is a bare address, not CIDR notation.
            if gw.parse::<std::net::IpAddr>().is_err() {
                return Err(AppError::validation(
                    "cloud-init gateway contains an invalid address",
                ));
            }
        }
        ensure_safe_id(&net.interface)?;
        for dns in &net.dns {
            if dns.chars().any(|c| c.is_control() || c == ':') || dns.trim().is_empty() {
                return Err(AppError::validation(
                    "cloud-init DNS servers must be plain IPv4 addresses",
                ));
            }
        }
    }
    if let Some(pw) = req.root_password.as_deref() {
        if base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pw).is_err() {
            return Err(AppError::validation("root_password must be base64-encoded"));
        }
    }
    Ok(())
}

/// Render the NoCloud `meta-data` file (instance id + local hostname).
fn cloud_init_meta_data(req: &CloudInitRequest, instance_id: &str) -> String {
    let hostname = req.hostname.as_deref().unwrap_or("daygleve-vm");
    format!("instance-id: {instance_id}\nlocal-hostname: {hostname}\n")
}

/// Render the NoCloud `user-data` file. Values were validated by
/// [`validate_cloud_init`] before this is called.
fn cloud_init_user_data(req: &CloudInitRequest) -> String {
    let user = req
        .default_user
        .clone()
        .unwrap_or_else(|| "daygleve".to_string());
    let mut b = String::from("#cloud-config\n");
    b.push_str(&format!(
        "hostname: {}\n",
        req.hostname.as_deref().unwrap_or("daygleve-vm")
    ));
    b.push_str("manage_etc_hosts: true\n");
    b.push_str("users:\n");
    b.push_str(&format!(
        "  - name: {user}\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    groups: sudo\n    shell: /bin/bash\n    lock_passwd: true\n"
    ));
    if !req.ssh_keys.is_empty() {
        b.push_str("ssh_authorized_keys:\n");
        for key in &req.ssh_keys {
            b.push_str(&format!("    - {key}\n"));
        }
    }
    if let Some(net) = req.network.as_ref() {
        b.push_str("write_files:\n");
        b.push_str("  - path: /etc/network/interfaces.d/50-cloud-init\n");
        b.push_str("    permissions: '0644'\n    content: |\n");
        b.push_str(&format!("      auto {}\n", net.interface));
        b.push_str(&format!("      iface {} inet static\n", net.interface));
        b.push_str(&format!("      address {}\n", net.address));
        if let Some(gw) = net.gateway.as_deref() {
            b.push_str(&format!("      gateway {gw}\n"));
        }
        if !net.dns.is_empty() {
            b.push_str(&format!("      dns-nameservers {}\n", net.dns.join(" ")));
        }
    }
    if let Some(pw) = req.root_password.as_deref() {
        // Already validated as base64; chpasswd expects `user:plaintext`,
        // so decode here and embed via the plain chpasswd list format.
        if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, pw)
        {
            let plain = String::from_utf8_lossy(&decoded);
            b.push_str("chpasswd:\n  expire: false\n  users:\n");
            b.push_str(&format!("    - name: {user}\n      password: {plain}\n"));
            b.push_str(&format!("    - name: root\n      password: {plain}\n"));
        }
    }
    b
}

/// Render libvirt domain XML for a VM. `spice_listen` is the address a SPICE
/// display binds to (ignored for VNC, which stays on localhost behind the
/// backend's websocket proxy).
fn domain_xml(vm: &Vm, spice_listen: &str) -> String {
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
    let cloud_init_cdrom: String = vm
        .cloud_init_iso
        .as_deref()
        .map(cloud_init_cdrom_xml)
        .unwrap_or_default();
    let nics: String = vm.nics.iter().map(nic_xml).collect();
    let hostdevs: String = vm
        .gpus
        .iter()
        .filter_map(|g| pci_hostdev_xml(&g.pci_address))
        .chain(
            vm.pci_devices
                .iter()
                .filter_map(|p| pci_hostdev_xml(&p.pci_address)),
        )
        .chain(
            vm.usb_devices
                .iter()
                .filter_map(|u| usb_hostdev_xml(&u.vendor_id, &u.product_id)),
        )
        .collect();
    let guest_agent_channel: String = if vm.guest_agent {
        guest_agent_channel_xml()
    } else {
        String::new()
    };
    let description = vm
        .description
        .as_deref()
        .map(|d| format!("  <description>{}</description>\n", xml_escape(d)))
        .unwrap_or_default();

    // Graphics + video are chosen by display protocol. VNC stays on localhost
    // (the backend proxies it to the browser via noVNC); SPICE binds the
    // configured address so an external remote-viewer can reach it, paired with
    // a QXL model for the richer SPICE features.
    let graphics = match vm.display {
        DisplayProtocol::Vnc => {
            "<graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'/>\n    \
             <video><model type='virtio' heads='1'/></video>"
                .to_string()
        }
        DisplayProtocol::Spice => format!(
            "<graphics type='spice' autoport='yes' listen='{listen}'>\
             <image compression='off'/></graphics>\n    \
             <video><model type='qxl' ram='65536' vram='65536' heads='1'/></video>",
            listen = xml_escape(spice_listen),
        ),
    };

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
        {disks}{cdrom}{cloud_init_cdrom}{nics}{hostdevs}    \
        {guest_agent_channel}    \
        {graphics}\n    \
        <memballoon model='virtio'/>\n    \
        <serial type='pty'><target type='isa-serial' port='0'/></serial>\n    \
        <console type='pty'><target type='serial' port='0'/></console>\n  \
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
        cloud_init_cdrom = cloud_init_cdrom,
        nics = nics,
        hostdevs = hostdevs,
        guest_agent_channel = guest_agent_channel,
        graphics = graphics,
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

/// A cloud-init NoCloud seed ISO attached as a second CD-ROM. Uses target `sdab` so
/// it never collides with the install-media CD-ROM at `sdaa` or data disks.
fn cloud_init_cdrom_xml(iso_path: &str) -> String {
    format!(
        "    <disk type='file' device='cdrom'>\n      \
        <driver name='qemu' type='raw'/>\n      \
        <source file='{iso}'/>\n        <target dev='sdab' bus='sata'/>\n      \
        <readonly/>\n    \
        </disk>\n",
        iso = xml_escape(iso_path),
    )
}

/// The virtio-serial QEMU guest agent channel. This gives the guest a named serial
/// channel the qemu-guest-agent daemon connects to. The unix socket source is
/// deliberately omitted: libvirt then auto-allocates
/// `/var/lib/libvirt/qemu/channel/target/<domain>-org.qemu.guest_agent.0` with the
/// correct ownership and SELinux/AppArmor labels, which a hand-built path would
/// not get. Without this element the guest agent cannot communicate with the
/// hypervisor; with it the guest can report IPs, accept shutdown requests, and
/// participate in fs-freeze/thaw for consistent snapshots.
fn guest_agent_channel_xml() -> String {
    "    <channel type='unix'>\n      \
        <target type='virtio' name='org.qemu.guest_agent.0'/>\n    \
        </channel>\n"
        .to_string()
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
    ensure_safe_pci_address(pci_address).ok()?;
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

/// A `<hostdev>` USB passthrough element matched by USB vendor:product. Returns
/// `None` for a malformed id so a bad value can never reach the domain XML.
fn usb_hostdev_xml(vendor_id: &str, product_id: &str) -> Option<String> {
    if !crate::services::is_hex4(vendor_id) || !crate::services::is_hex4(product_id) {
        return None;
    }
    Some(format!(
        "    <hostdev mode='subsystem' type='usb'>\n      \
        <source><vendor id='0x{vendor_id}'/><product id='0x{product_id}'/></source>\n    \
        </hostdev>\n",
    ))
}

/// Validate general PCI passthrough assignments: each address must pass the
/// PCI-address sanitizer (it becomes a `<hostdev>` source and a sysfs path).
fn validate_pci_assignments(devices: &[daygleve_schema::pci::PciAssignment]) -> ApiResult<()> {
    for dev in devices {
        ensure_safe_pci_address(&dev.pci_address)?;
    }
    Ok(())
}

/// Validate USB passthrough assignments: each id must be four hex digits (the
/// USB `vendor`/`product` shape), or the resulting `<hostdev>` would be
/// malformed.
fn validate_usb_assignments(devices: &[daygleve_schema::usb::UsbAssignment]) -> ApiResult<()> {
    for dev in devices {
        if !crate::services::is_hex4(&dev.vendor_id) || !crate::services::is_hex4(&dev.product_id) {
            return Err(AppError::validation(format!(
                "USB id must be four hex digits: {}:{}",
                dev.vendor_id, dev.product_id
            )));
        }
    }
    Ok(())
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
    use base64::Engine;
    use daygleve_schema::vm::VmFirewallRule;

    fn sample_vm() -> Vm {
        Vm {
            id: new_id(),
            name: "web01".to_string(),
            state: VmState::Stopped,
            vcpus: 2,
            memory_mib: 2048,
            firmware: Firmware::Uefi,
            display: DisplayProtocol::Vnc,
            disks: vec![VmDisk {
                dataset: "tank/vms/web01-disk0".to_string(),
                size_gib: 20,
                bus: DiskBus::Virtio,
            }],
            nics: vec![],
            gpus: vec![],
            usb_devices: vec![],
            pci_devices: vec![],
            cdrom: None,
            cloud_init_iso: None,
            description: None,
            guest_agent: false,
            firewall: VmFirewall::default(),
            template: false,
            autostart: false,
            startup_order: None,
            tags: vec![],
            pool: None,
            created_at: now_ts(),
            updated_at: None,
        }
    }

    #[test]
    fn autostart_queue_orders_and_filters() {
        let mk =
            |name: &str, autostart: bool, template: bool, order: Option<u32>, created: &str| {
                let mut vm = sample_vm();
                vm.id = new_id();
                vm.name = name.to_string();
                vm.autostart = autostart;
                vm.template = template;
                vm.startup_order = order;
                vm.created_at = created.to_string();
                vm
            };
        let vms = vec![
            mk(
                "no-autostart",
                false,
                false,
                Some(1),
                "2020-01-01T00:00:00Z",
            ),
            mk("template", true, true, Some(0), "2020-01-01T00:00:00Z"),
            mk("third-unordered", true, false, None, "2020-01-03T00:00:00Z"),
            mk("second", true, false, Some(20), "2020-01-01T00:00:00Z"),
            mk("first", true, false, Some(5), "2020-01-01T00:00:00Z"),
            mk(
                "fourth-unordered",
                true,
                false,
                None,
                "2020-01-04T00:00:00Z",
            ),
        ];
        let order: Vec<String> = autostart_queue(vms).into_iter().map(|vm| vm.name).collect();
        // Templates and non-autostart VMs are excluded; ordered VMs come first
        // (5 then 20), then unordered VMs by creation time.
        assert_eq!(
            order,
            vec!["first", "second", "third-unordered", "fourth-unordered"]
        );
    }

    #[test]
    fn domain_xml_renders_usb_hostdevs_and_drops_bad_ids() {
        use daygleve_schema::usb::UsbAssignment;
        let mut vm = sample_vm();
        vm.usb_devices = vec![
            UsbAssignment {
                vendor_id: "1d6b".into(),
                product_id: "0003".into(),
            },
            // A malformed id must not reach the XML.
            UsbAssignment {
                vendor_id: "zzzz".into(),
                product_id: "0003".into(),
            },
        ];
        let xml = domain_xml(&vm, "127.0.0.1");
        assert!(xml.contains("<hostdev mode='subsystem' type='usb'>"));
        assert!(xml.contains("<vendor id='0x1d6b'/><product id='0x0003'/>"));
        assert!(!xml.contains("0xzzzz"), "malformed id must be dropped");
    }

    #[test]
    fn domain_xml_renders_pci_hostdevs() {
        use daygleve_schema::pci::PciAssignment;
        let mut vm = sample_vm();
        vm.pci_devices = vec![PciAssignment {
            pci_address: "0000:03:00.0".into(),
        }];
        let xml = domain_xml(&vm, "127.0.0.1");
        assert!(xml.contains("<hostdev mode='subsystem' type='pci' managed='yes'>"));
        assert!(xml.contains("domain='0x0000' bus='0x03' slot='0x00' function='0x0'"));
    }

    #[test]
    fn pci_assignments_are_validated() {
        use daygleve_schema::pci::PciAssignment;
        assert!(validate_pci_assignments(&[PciAssignment {
            pci_address: "0000:03:00.0".into(),
        }])
        .is_ok());
        // A traversal/flag-shaped address is rejected by the sanitizer.
        assert!(validate_pci_assignments(&[PciAssignment {
            pci_address: "../etc".into(),
        }])
        .is_err());
    }

    #[test]
    fn usb_assignments_are_validated() {
        use daygleve_schema::usb::UsbAssignment;
        assert!(validate_usb_assignments(&[UsbAssignment {
            vendor_id: "1d6b".into(),
            product_id: "0003".into(),
        }])
        .is_ok());
        for (v, p) in [("1d6", "0003"), ("1d6b", "003"), ("g1d6", "0003"), ("", "")] {
            assert!(
                validate_usb_assignments(&[UsbAssignment {
                    vendor_id: v.into(),
                    product_id: p.into(),
                }])
                .is_err(),
                "{v}:{p} must be rejected"
            );
        }
    }

    #[test]
    fn usb_and_pci_hostdev_xml_round_trip() {
        let usb = usb_hostdev_xml("1d6b", "0003").expect("valid ids render xml");
        assert!(usb.contains("type='usb'"));
        assert!(usb.contains("vendor id='0x1d6b'"));
        assert!(usb.contains("product id='0x0003'"));
        assert!(usb_hostdev_xml("1d6", "0003").is_none());

        let pci = pci_hostdev_xml("0000:01:00.0").expect("valid address renders xml");
        assert!(pci.contains("type='pci'"));
        assert!(pci.contains("domain='0x0000'"));
        assert!(pci.contains("bus='0x01'"));
        assert!(pci.contains("slot='0x00'"));
        assert!(pci.contains("function='0x0'"));
        assert!(pci_hostdev_xml("../../etc").is_none());
    }

    #[test]
    fn domain_xml_without_cdrom_boots_from_disk() {
        let xml = domain_xml(&sample_vm(), "127.0.0.1");
        assert!(xml.contains("<boot dev='hd'/>"), "should boot from disk");
        assert!(!xml.contains("device='cdrom'"), "no cdrom device");
        assert!(!xml.contains("<boot order="), "no per-device boot order");
    }

    #[test]
    fn domain_xml_with_cdrom_boots_from_media_then_disk() {
        let mut vm = sample_vm();
        vm.cdrom = Some("/var/lib/daygleve/isos/debian.iso".to_string());
        let xml = domain_xml(&vm, "127.0.0.1");

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
        let xml = domain_xml(&vm, "127.0.0.1");
        assert!(xml.contains("<os>\n"), "BIOS uses the plain <os> block");
        assert!(!xml.contains("firmware='efi'"), "BIOS is not EFI");
        assert!(xml.contains("<boot dev='hd'/>"), "BIOS boots from disk");

        // BIOS with media: switches to the boot menu + per-device order.
        vm.cdrom = Some("/var/lib/daygleve/isos/debian.iso".to_string());
        let xml = domain_xml(&vm, "127.0.0.1");
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
    fn generated_macs_are_well_formed() {
        let mac = generate_mac();
        assert!(mac.starts_with("52:54:00:"), "unexpected MAC: {mac}");
        let octets: Vec<&str> = mac.split(':').collect();
        assert_eq!(octets.len(), 6, "MAC should have 6 octets: {mac}");
        for o in octets {
            assert_eq!(o.len(), 2, "each octet is two hex digits: {mac}");
            assert!(
                o.bytes().all(|b| b.is_ascii_hexdigit()),
                "octet not hex: {mac}"
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

    #[test]
    fn domain_xml_renders_guest_agent_and_cloud_init_channels() {
        let mut vm = sample_vm();
        vm.guest_agent = true;
        vm.cloud_init_iso = Some("/var/lib/daygleve/cloud-init/web01-seed.iso".to_string());
        let xml = domain_xml(&vm, "127.0.0.1");
        // The agent channel targets the well-known virtio name and lets libvirt
        // allocate the unix socket itself.
        assert!(xml.contains("<channel type='unix'>"));
        assert!(xml.contains("<target type='virtio' name='org.qemu.guest_agent.0'/>"));
        // The NoCloud seed rides a second SATA CD-ROM outside the data-disk
        // target scheme, and carries no boot order (never a boot device).
        assert!(xml.contains("<target dev='sdab' bus='sata'/>"));
        assert!(xml.contains("<source file='/var/lib/daygleve/cloud-init/web01-seed.iso'/>"));
        // Disabled agent renders no channel at all.
        let mut off = sample_vm();
        off.guest_agent = false;
        assert!(!domain_xml(&off, "127.0.0.1").contains("<channel"));
    }

    #[test]
    fn spice_display_renders_qxl_graphics() {
        let mut vm = sample_vm();
        vm.display = DisplayProtocol::Spice;
        let xml = domain_xml(&vm, "10.0.0.5");
        assert!(xml.contains("<graphics type='spice' autoport='yes' listen='10.0.0.5'>"));
        assert!(xml.contains("<model type='qxl'"));
        assert!(!xml.contains("type='vnc'"));
        // The default stays VNC on localhost.
        let vnc = domain_xml(&sample_vm(), "10.0.0.5");
        assert!(vnc.contains("<graphics type='vnc'"));
        assert!(!vnc.contains("type='spice'"));
    }

    #[test]
    fn spice_port_parses_uri_forms() {
        assert_eq!(parse_spice_port("spice://127.0.0.1:5901"), Some(5901));
        assert_eq!(parse_spice_port("spice://127.0.0.1?port=5902"), Some(5902));
        assert_eq!(
            parse_spice_port("spice://host?tls-port=5903&port=5904"),
            Some(5904)
        );
        assert_eq!(parse_spice_port("spice://127.0.0.1"), None);
        assert_eq!(parse_spice_port(""), None);
    }

    #[test]
    fn qemu_img_virtual_size_is_extracted() {
        let json = r#"{"virtual-size": 21474836480, "filename": "x.qcow2", "format": "qcow2", "actual-size": 1048576}"#;
        assert_eq!(parse_qemu_img_virtual_size(json).unwrap(), 21474836480);
        // A 20 GiB image rounds to exactly 20 GiB.
        assert_eq!(21474836480u64.div_ceil(1024 * 1024 * 1024).max(1), 20);
        // A size that isn't a whole GiB rounds up.
        assert_eq!((21474836480u64 + 1).div_ceil(1024 * 1024 * 1024).max(1), 21);
        // Missing/garbage output is an error rather than a silent zero.
        assert!(parse_qemu_img_virtual_size("{}").is_err());
        assert!(parse_qemu_img_virtual_size("not json").is_err());
    }

    #[test]
    fn spice_connection_file_is_a_virt_viewer_ini() {
        let vv = spice_connection_file("web01", "10.0.0.5", 5901);
        assert!(vv.starts_with("[virt-viewer]\n"));
        assert!(vv.contains("type=spice\n"));
        assert!(vv.contains("host=10.0.0.5\n"));
        assert!(vv.contains("port=5901\n"));
        assert!(vv.contains("delete-this-file=1\n"));
    }

    #[test]
    fn domain_xml_renders_serial_and_console_pty() {
        // Every VM gets a pty-backed serial port plus a console aliased to it,
        // so `virsh ttyconsole` resolves a device for the text console.
        let xml = domain_xml(&sample_vm(), "127.0.0.1");
        assert!(xml.contains("<serial type='pty'><target type='isa-serial' port='0'/></serial>"));
        assert!(xml.contains("<console type='pty'><target type='serial' port='0'/></console>"));
    }

    #[test]
    fn nft_firewall_batch_filters_only_vm_traffic() {
        let mut vm = sample_vm();
        vm.nics.push(VmNic {
            bridge: "vmbr0".to_string(),
            vlan: None,
            mac: Some("52:54:00:12:34:56".to_string()),
            model: NicModel::Virtio,
        });
        vm.firewall = VmFirewall {
            enabled: true,
            rules: vec![
                VmFirewallRule {
                    direction: VmFirewallDirection::In,
                    action: VmFirewallAction::Accept,
                    cidr: Some("192.168.1.0/24".to_string()),
                    description: None,
                },
                VmFirewallRule {
                    direction: VmFirewallDirection::Out,
                    action: VmFirewallAction::AcceptAll,
                    cidr: None,
                    description: None,
                },
            ],
        };
        let batch = nft_firewall_batch("daygleve_vm_x", &vm.firewall, &vm.nics).unwrap();
        assert!(batch.contains("add table inet daygleve_vm_x"));
        assert!(batch.contains("hook forward priority -100"));
        assert!(batch.contains("ct state established,related accept"));
        assert!(batch.contains("ether saddr 52:54:00:12:34:56"));
        assert!(batch.contains("ip saddr 192.168.1.0/24"));
        // The outbound accept-all rule has no CIDR match, just the verdict;
        // MACs are matched once in the jump rule, not repeated per rule.
        assert!(batch.contains("vm_daygleve_vm_x_rules ether saddr accept"));
        assert!(batch.contains("jump vm_daygleve_vm_x_rules"));
    }

    #[test]
    fn nft_firewall_batch_requires_a_valid_mac() {
        let fw = VmFirewall {
            enabled: true,
            rules: vec![],
        };
        assert!(nft_firewall_batch("t", &fw, &[]).is_err());
        let bad = VmNic {
            bridge: "vmbr0".to_string(),
            vlan: None,
            mac: Some("not-a-mac".to_string()),
            model: NicModel::Virtio,
        };
        assert!(nft_firewall_batch("t", &fw, &[bad]).is_err());
    }

    #[test]
    fn firewall_validation_enforces_cidr_rules() {
        // accept/drop require a CIDR; *_all forbid one.
        assert!(validate_firewall(&VmFirewall {
            enabled: true,
            rules: vec![VmFirewallRule {
                direction: VmFirewallDirection::In,
                action: VmFirewallAction::Accept,
                cidr: None,
                description: None,
            }],
        })
        .is_err());
        assert!(validate_firewall(&VmFirewall {
            enabled: true,
            rules: vec![VmFirewallRule {
                direction: VmFirewallDirection::In,
                action: VmFirewallAction::Accept,
                cidr: Some("10.0.0.0/8".to_string()),
                description: None,
            }],
        })
        .is_ok());
        assert!(validate_firewall(&VmFirewall {
            enabled: true,
            rules: vec![VmFirewallRule {
                direction: VmFirewallDirection::Out,
                action: VmFirewallAction::AcceptAll,
                cidr: Some("10.0.0.0/8".to_string()),
                description: None,
            }],
        })
        .is_err());
        assert!(validate_firewall(&VmFirewall {
            enabled: true,
            rules: vec![VmFirewallRule {
                direction: VmFirewallDirection::Out,
                action: VmFirewallAction::Drop,
                cidr: Some("10.0.0.0/33".to_string()),
                description: None,
            }],
        })
        .is_err());
    }

    #[test]
    fn cloud_init_files_render_yaml_and_metadata() {
        let req = CloudInitRequest {
            hostname: Some("web01".to_string()),
            network: Some(daygleve_schema::vm::CloudInitNetwork {
                interface: "eth0".to_string(),
                address: "192.168.1.10/24".to_string(),
                gateway: Some("192.168.1.1".to_string()),
                dns: vec!["192.168.1.1".to_string()],
            }),
            ssh_keys: vec!["ssh-ed25519 AAAA test@host".to_string()],
            default_user: Some("deploy".to_string()),
            root_password: None,
        };
        assert!(validate_cloud_init(&req).is_ok());
        let meta = cloud_init_meta_data(&req, "iid-123");
        assert!(meta.contains("instance-id: iid-123"));
        assert!(meta.contains("local-hostname: web01"));
        let user = cloud_init_user_data(&req);
        assert!(user.starts_with("#cloud-config\n"));
        assert!(user.contains("name: deploy"));
        assert!(user.contains("- ssh-ed25519 AAAA test@host"));
        assert!(user.contains("address 192.168.1.10/24"));
        assert!(user.contains("gateway 192.168.1.1"));
    }

    #[test]
    fn cloud_init_rejects_unsafe_values() {
        let mut req = CloudInitRequest {
            hostname: Some("../escape".to_string()),
            network: None,
            ssh_keys: vec![],
            default_user: None,
            root_password: None,
        };
        assert!(validate_cloud_init(&req).is_err());
        req.hostname = Some("ok".to_string());
        req.root_password = Some("not base64!".to_string());
        assert!(validate_cloud_init(&req).is_err());
        req.root_password = Some(base64::engine::general_purpose::STANDARD.encode("secret"));
        assert!(validate_cloud_init(&req).is_ok());
    }

    #[test]
    fn domifaddr_and_guest_info_parsers() {
        let ips = parse_domifaddr_ips(
            "Name       MAC address        Protocol     Address\n\nvirtio0  52:54:00:ab:cd:ef  ipv4   10.0.0.5/24\nvirtio0  52:54:00:ab:cd:ef  ipv6   fe80::1/64\n",
        );
        assert_eq!(ips, vec!["10.0.0.5", "fe80::1"]);
        let info = "return: 0\npretty_name: Debian GNU/Linux 13\nversion: 1.2";
        assert_eq!(
            parse_guest_info_field(info, "pretty_name").as_deref(),
            Some("Debian GNU/Linux 13")
        );
        assert_eq!(parse_guest_info_field(info, "missing"), None);
    }

    #[test]
    fn ram_snapshot_paths_stay_in_state_dir() {
        let config = Arc::new(crate::config::Config::from_env());
        let service = KvmService::new(
            config.clone(),
            Arc::new(crate::services::shares::ShareService::new(config)),
        );
        assert!(service.ram_snapshot_path("pre-upgrade").is_ok());
        assert!(service.ram_snapshot_path("../escape").is_err());
    }
}
