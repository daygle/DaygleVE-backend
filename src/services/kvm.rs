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

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use daygleve_schema::vm::{
    ConsoleTicket, CreateVmRequest, DiskBus, Firmware, NicModel, UpdateVmRequest, Vm, VmDisk,
    VmNic, VmPowerAction, VmState, VmSummary,
};

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::store::JsonStore;
use crate::services::{command, new_id, now_ts};

/// How long a console ticket is valid before the client must re-request one.
const TICKET_TTL: Duration = Duration::from_secs(60);

/// A pending console ticket bound to a domain's VNC socket.
struct Ticket {
    vm_id: String,
    vnc_addr: String,
    expires_at: Instant,
}

pub struct KvmService {
    store: JsonStore,
    config: Arc<Config>,
    tickets: RwLock<HashMap<String, Ticket>>,
}

impl KvmService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            store: JsonStore::new(&config.state_dir, "vms"),
            config,
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
        if req.vcpus == 0 {
            return Err(AppError::validation("vcpus must be >= 1"));
        }
        if req.memory_mib == 0 {
            return Err(AppError::validation("memory_mib must be >= 1"));
        }

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
        if req.description.is_some() {
            vm.description = req.description;
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
        self.tickets.write().expect("ticket lock").insert(
            ticket.clone(),
            Ticket {
                vm_id: id.to_string(),
                vnc_addr,
                expires_at: Instant::now() + TICKET_TTL,
            },
        );

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

    /// Write the domain XML and (re)define it in libvirt.
    async fn define(&self, vm: &Vm) -> ApiResult<()> {
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
        let size = format!("{}G", disk.size_gib);
        match command::run_optional("zfs", &["create", "-V", &size, &disk.dataset]).await {
            Ok(_) => Ok(()),
            // Reusing an existing dataset is fine.
            Err(e) if format!("{e:?}").contains("exists") => Ok(()),
            Err(e) => Err(e),
        }
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

/// Parse `virsh vncdisplay` output (`host:N` or `:N`) to a `host:port` socket.
fn parse_vnc_display(display: &str) -> Option<String> {
    let (host, disp) = display.rsplit_once(':')?;
    let n: u16 = disp.trim().parse().ok()?;
    let host = if host.is_empty() { "127.0.0.1" } else { host };
    Some(format!("{host}:{}", 5900 + n))
}

/// Render libvirt domain XML for a VM.
fn domain_xml(vm: &Vm) -> String {
    let os = match vm.firmware {
        Firmware::Uefi => {
            "<os firmware='efi'>\n    <type arch='x86_64' machine='q35'>hvm</type>\n    <boot dev='hd'/>\n  </os>"
                .to_string()
        }
        Firmware::Bios => {
            "<os>\n    <type arch='x86_64' machine='q35'>hvm</type>\n    <boot dev='hd'/>\n  </os>"
                .to_string()
        }
    };

    let disks: String = vm
        .disks
        .iter()
        .enumerate()
        .map(|(i, d)| disk_xml(i, d))
        .collect();
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
        {disks}{nics}{hostdevs}    \
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
        nics = nics,
        hostdevs = hostdevs,
    )
}

fn disk_xml(index: usize, disk: &VmDisk) -> String {
    let (target, bus) = disk_target(disk.bus, index);
    format!(
        "    <disk type='block' device='disk'>\n      \
        <driver name='qemu' type='raw' cache='none' io='native'/>\n      \
        <source dev='/dev/zvol/{dataset}'/>\n      \
        <target dev='{target}' bus='{bus}'/>\n    \
        </disk>\n",
        dataset = xml_escape(&disk.dataset),
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
