//! LXC container lifecycle service.
//!
//! Drives the `lxc-*` tooling with a ZFS-backed rootfs (`lxc-create -B zfs`).
//! As with VMs, LXC persists the container config/rootfs itself and DaygleVE
//! keeps a sidecar record of the structured `Lxc`, overlaying live state from
//! `lxc-info` at read time. CPU/memory limits and veth networking are written
//! into the container config at create time.
//!
//! This is the least host-portable of the services: it needs a ZFS-capable
//! `lxc`. A container's rootfs comes either from the `download` template server
//! (`<dist>-<release>`, e.g. `debian-bookworm`) or from an uploaded CT-template
//! tarball in the node's local library, built via the `local` template's
//! `--fstree`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use daygleve_schema::lxc::{
    CreateLxcRequest, Lxc, LxcMount, LxcNetwork, LxcPowerAction, LxcState, LxcSummary,
    UpdateLxcRequest,
};
use daygleve_schema::vm::ConsoleTicket;

use daygleve_schema::lxc_snapshot::LxcSnapshotRecord;

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::library::LibraryService;
use crate::services::store::JsonStore;
use crate::services::{
    command, ensure_safe_cidr, ensure_safe_id, ensure_safe_zfs_dataset, new_id, now_ts,
};

/// How long a console ticket is valid before the client must re-request one.
const TICKET_TTL: Duration = Duration::from_secs(60);

/// A pending console ticket bound to a container.
struct ConsoleTicketEntry {
    container_id: String,
    name: String,
    expires_at: Instant,
}

pub struct LxcService {
    store: JsonStore,
    config: Arc<Config>,
    /// Resolves uploaded CT-template file names to on-disk paths.
    library: LibraryService,
    /// Pending one-time console tickets, keyed by the opaque ticket.
    tickets: RwLock<HashMap<String, ConsoleTicketEntry>>,
}

impl LxcService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            store: JsonStore::new(&config.state_dir, "containers"),
            library: LibraryService::new(config.clone()),
            config,
            tickets: RwLock::new(HashMap::new()),
        }
    }

    pub async fn list(&self) -> ApiResult<Vec<LxcSummary>> {
        let cts: Vec<Lxc> = self.store.list().await?;
        let mut out = Vec::with_capacity(cts.len());
        for mut ct in cts {
            ct.state = self.live_state(&ct.name).await.unwrap_or(ct.state);
            out.push(summary_of(&ct));
        }
        Ok(out)
    }

    /// Mint a one-time ticket for the container's console. Requires the
    /// container to be running; the console is opened later, through the broker,
    /// when the websocket redeems the ticket.
    pub async fn console(&self, id: &str) -> ApiResult<ConsoleTicket> {
        let ct = self.get_stored(id).await?;
        if !matches!(self.live_state(&ct.name).await, Some(LxcState::Running)) {
            return Err(AppError::conflict("start the container to open a console"));
        }
        let ticket = new_id();
        {
            let mut tickets = self.tickets.write().expect("ticket lock");
            let now = Instant::now();
            tickets.retain(|_, t| t.expires_at > now);
            tickets.insert(
                ticket.clone(),
                ConsoleTicketEntry {
                    container_id: id.to_string(),
                    name: ct.name.clone(),
                    expires_at: now + TICKET_TTL,
                },
            );
        }
        Ok(ConsoleTicket {
            websocket_path: format!("/api/v1/containers/{id}/console/ws?ticket={ticket}"),
            ticket,
            expires_at: (chrono::Utc::now() + chrono::Duration::from_std(TICKET_TTL).unwrap())
                .to_rfc3339(),
        })
    }

    /// Validate and consume a console ticket, returning the container name to
    /// attach to. One-time: the ticket is removed on a valid match.
    pub fn redeem_console_ticket(&self, container_id: &str, ticket: &str) -> ApiResult<String> {
        let mut tickets = self.tickets.write().expect("ticket lock");
        match tickets.get(ticket) {
            Some(t) if t.container_id == container_id && t.expires_at > Instant::now() => {
                Ok(tickets.remove(ticket).expect("ticket present").name)
            }
            _ => Err(AppError::unauthorized("invalid or expired console ticket")),
        }
    }

    /// Open a live bridge to a container console (through the broker on the
    /// appliance). The name comes from a previously-redeemed console ticket.
    pub async fn attach_console(
        &self,
        name: &str,
    ) -> ApiResult<(command::ConsoleReadHalf, command::ConsoleWriteHalf)> {
        command::lxc_console_attach(name).await
    }

    pub async fn get(&self, id: &str) -> ApiResult<Lxc> {
        let mut ct = self.get_stored(id).await?;
        ct.state = self.live_state(&ct.name).await.unwrap_or(ct.state);
        Ok(ct)
    }

    pub async fn create(&self, req: CreateLxcRequest) -> ApiResult<Lxc> {
        if req.name.trim().is_empty() {
            return Err(AppError::validation("name must not be empty"));
        }
        // The name becomes the container name and its config path; keep it safe.
        crate::services::ensure_safe_id(&req.name)?;
        if req.vcpus == 0 {
            return Err(AppError::validation("vcpus must be >= 1"));
        }
        if req.memory_mib == 0 {
            // Written into lxc.cgroup2.memory.max; 0 would be an unusable limit.
            return Err(AppError::validation("memory_mib must be >= 1"));
        }
        if req.rootfs_size_gib == 0 {
            return Err(AppError::validation("rootfs_size_gib must be >= 1"));
        }
        for network in &req.networks {
            ensure_safe_id(&network.bridge)?;
            if let Some(vlan) = network.vlan {
                if !(1..=4094).contains(&vlan) {
                    return Err(AppError::validation("container VLAN must be in 1..=4094"));
                }
            }
            if let Some(ip) = network.ip.as_deref() {
                ensure_safe_cidr(ip, "network.ip")?;
            }
        }
        for mount in &req.mounts {
            validate_mount(mount)?;
        }

        // Two rootfs sources: an uploaded CT-template tarball (built with the
        // `local` template's `--fstree`), or a `<dist>-<release>` image pulled
        // from the LXC download server. When a template file is given the
        // `template` field is only a descriptive label; otherwise it must parse
        // as `<dist>-<release>`.
        let template_file = match req.template_file.as_deref() {
            Some(name) => Some(self.library.resolve_ct_template(name).await?),
            None => None,
        };
        let dist_release = if template_file.is_none() {
            let (dist, release) = req.template.split_once('-').ok_or_else(|| {
                AppError::validation("template must be <dist>-<release>, e.g. debian-bookworm")
            })?;
            if dist.is_empty()
                || release.is_empty()
                || !dist.bytes().all(|b| b.is_ascii_alphanumeric())
                || !release
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
            {
                return Err(AppError::validation("template contains invalid characters"));
            }
            Some((dist.to_string(), release.to_string()))
        } else {
            None
        };

        ensure_safe_zfs_dataset(&self.config.default_pool)?;
        let zfsroot = format!("{}/lxc", self.config.default_pool);
        let rootfs_dataset = format!("{zfsroot}/{}", req.name);

        // Create the container with a ZFS-backed rootfs, either from the
        // uploaded tarball (local template) or a download image.
        if let Some(fstree) = template_file.as_deref() {
            let fstree = fstree.to_string_lossy();
            command::run_ok(
                "lxc-create",
                &[
                    "-n",
                    &req.name,
                    "-B",
                    "zfs",
                    "--zfsroot",
                    &zfsroot,
                    "-t",
                    "local",
                    "--",
                    "--fstree",
                    &fstree,
                ],
            )
            .await?;
        } else {
            let (dist, release) = dist_release
                .as_ref()
                .expect("dist/release when no template file");
            command::run_ok(
                "lxc-create",
                &[
                    "-n",
                    &req.name,
                    "-B",
                    "zfs",
                    "--zfsroot",
                    &zfsroot,
                    "-t",
                    "download",
                    "--",
                    "--dist",
                    dist,
                    "--release",
                    release,
                    "--arch",
                    "amd64",
                ],
            )
            .await?;
        }

        // Apply a rootfs quota (best-effort) and write limits + networking. If
        // writing the config fails, the container/rootfs already exist on the
        // host — tear them down so we don't leave an orphan the record never
        // tracks.
        let quota = format!("quota={}G", req.rootfs_size_gib);
        if let Err(e) = command::run_ok("zfs", &["set", &quota, &rootfs_dataset]).await {
            let _ = command::run_optional("lxc-destroy", &["-n", &req.name, "-f"]).await;
            let _ = command::run_optional("zfs", &["destroy", "-r", &rootfs_dataset]).await;
            return Err(e);
        }
        if let Err(e) = self
            .write_config(
                &req.name,
                req.vcpus,
                req.memory_mib,
                &req.networks,
                &req.mounts,
            )
            .await
        {
            let _ = command::run_optional("lxc-destroy", &["-n", &req.name, "-f"]).await;
            let _ = command::run_optional("zfs", &["destroy", "-r", &rootfs_dataset]).await;
            return Err(e);
        }

        let ct = Lxc {
            id: new_id(),
            name: req.name.clone(),
            state: LxcState::Stopped,
            template: req.template,
            rootfs_dataset,
            vcpus: req.vcpus,
            memory_mib: req.memory_mib,
            networks: req.networks,
            mounts: req.mounts,
            unprivileged: req.unprivileged,
            description: req.description,
            created_at: now_ts(),
            updated_at: None,
        };

        let mut ct = ct;
        if req.start {
            command::run_ok("lxc-start", &["-n", &ct.name, "-d"]).await?;
            ct.state = LxcState::Running;
        }
        self.store.put(&ct.id, &ct).await?;
        Ok(ct)
    }

    pub async fn update(&self, id: &str, req: UpdateLxcRequest) -> ApiResult<Lxc> {
        let mut ct = self.get_stored(id).await?;
        if req.name.is_some() {
            // The container name is also its config path and the handle every
            // lxc-* call targets; renaming needs a real host-side rename, which
            // isn't implemented yet. Reject rather than silently desync.
            return Err(AppError::validation(
                "renaming a container is not supported yet",
            ));
        }
        if let Some(vcpus) = req.vcpus {
            if vcpus == 0 {
                return Err(AppError::validation("vcpus must be >= 1"));
            }
            ct.vcpus = vcpus;
        }
        if let Some(mem) = req.memory_mib {
            if mem == 0 {
                // 0 would write an unusable cgroup memory limit (as on create).
                return Err(AppError::validation("memory_mib must be >= 1"));
            }
            ct.memory_mib = mem;
        }
        if req.description.is_some() {
            ct.description = req.description;
        }

        // Apply new limits live if the container is running (best-effort).
        if matches!(self.live_state(&ct.name).await, Some(LxcState::Running)) {
            let mem_bytes = (ct.memory_mib * 1024 * 1024).to_string();
            let _ =
                command::run_optional("lxc-cgroup", &["-n", &ct.name, "memory.max", &mem_bytes])
                    .await;
            let cpu_max = format!("{} 100000", ct.vcpus as u64 * 100_000);
            let _ =
                command::run_optional("lxc-cgroup", &["-n", &ct.name, "cpu.max", &cpu_max]).await;
        }

        ct.updated_at = Some(now_ts());
        self.store.put(id, &ct).await?;
        self.get(id).await
    }

    pub async fn delete(&self, id: &str) -> ApiResult<()> {
        let ct = self.get_stored(id).await?;
        let _ = command::run_optional("lxc-stop", &["-n", &ct.name, "-k"]).await;
        let _ = command::run_optional("lxc-destroy", &["-n", &ct.name, "-f"]).await;
        // lxc-destroy removes the zfs-backed rootfs; clean up any remnant.
        let _ = command::run_optional("zfs", &["destroy", "-r", &ct.rootfs_dataset]).await;
        self.store.delete(id).await?;
        Ok(())
    }

    pub async fn power(&self, id: &str, action: LxcPowerAction) -> ApiResult<Lxc> {
        let mut ct = self.get_stored(id).await?;
        match action {
            LxcPowerAction::Start => {
                command::run_ok("lxc-start", &["-n", &ct.name, "-d"]).await?;
            }
            LxcPowerAction::Stop => {
                command::run_ok("lxc-stop", &["-n", &ct.name]).await?;
            }
            LxcPowerAction::Restart => {
                let _ = command::run_optional("lxc-stop", &["-n", &ct.name]).await;
                command::run_ok("lxc-start", &["-n", &ct.name, "-d"]).await?;
            }
            LxcPowerAction::Freeze => {
                command::run_ok("lxc-freeze", &["-n", &ct.name]).await?;
            }
            LxcPowerAction::Unfreeze => {
                command::run_ok("lxc-unfreeze", &["-n", &ct.name]).await?;
            }
        }

        ct.state = self.live_state(&ct.name).await.unwrap_or(ct.state);
        ct.updated_at = Some(now_ts());
        self.store.put(id, &ct).await?;
        Ok(ct)
    }

    // --- internals -------------------------------------------------------

    async fn get_stored(&self, id: &str) -> ApiResult<Lxc> {
        self.store
            .get(id)
            .await?
            .ok_or_else(|| AppError::not_found(format!("container {id} not found")))
    }

    /// Live state from `lxc-info -sH`, or `None` if it can't be determined.
    async fn live_state(&self, name: &str) -> Option<LxcState> {
        match command::run_optional("lxc-info", &["-n", name, "-sH"]).await {
            Ok(Some(s)) => Some(map_lxc_state(s.trim())),
            _ => None,
        }
    }
    /// Append CPU/memory cgroup limits and vet the bridge name.
    ///
    /// Compare persisted container records to live lxc containers, returning findings
    /// about containers that exist in one but not the other.
    ///
    /// Read-only: never modifies the host or the store.
    pub async fn reconcile_with_host(&self) -> ApiResult<(Vec<String>, Vec<String>)> {
        let mut missing_in_host = Vec::new();
        let mut missing_in_store = Vec::new();
        let stored: Vec<Lxc> = self.store.list().await?;
        let stored_names: std::collections::HashSet<&str> =
            stored.iter().map(|ct| ct.name.as_str()).collect();

        // Containers that are in the store but not in lxc.
        for ct in &stored {
            let exists = match command::run_optional("lxc-info", &["-n", &ct.name, "-sH"]).await {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(_) => {
                    // If lxc-info can't be run, stop the comparison.
                    return Err(AppError::hypervisor(
                        "lxc-info is unavailable; cannot reconcile containers",
                    ));
                }
            };
            if !exists {
                missing_in_host.push(ct.id.clone());
            }
        }

        // Containers defined in lxc but not tracked in the store.
        let all_containers = self.list_all_containers().await?;
        for ct in all_containers {
            if !stored_names.contains(ct.name.as_str()) {
                missing_in_store.push(ct.name);
            }
        }

        Ok((missing_in_host, missing_in_store))
    }

    /// Recreate a persisted container definition when its host entry is absent.
    /// This deliberately does not start the container or recreate its rootfs.
    pub async fn repair_missing_from_host(&self, id: &str) -> ApiResult<()> {
        let ct = self.get_stored(id).await?;
        self.write_config(&ct.name, ct.vcpus, ct.memory_mib, &ct.networks, &ct.mounts)
            .await
    }

    /// All lxc containers visible on the host, as summaries.
    async fn list_all_containers(&self) -> ApiResult<Vec<LxcSummary>> {
        let out = match command::run_optional("lxc-ls", &["-1", "--nesting"]).await {
            Ok(Some(o)) => o,
            Ok(None) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };

        let mut out_vec = Vec::new();
        for line in out.lines().filter(|l| !l.trim().is_empty()) {
            out_vec.push(LxcSummary {
                id: line.trim().to_string(),
                name: line.trim().to_string(),
                state: LxcState::Stopped,
                vcpus: 0,
                memory_mib: 0,
                created_at: now_ts(),
            });
        }
        Ok(out_vec)
    }
    /// Snapshot a container's ZFS-backed rootfs. ZFS snapshots are
    /// crash-consistent, so capture works whether or not the container is
    /// running; rollback is the guarded operation, not capture.
    pub async fn snapshot(
        &self,
        id: &str,
        name: &str,
        description: Option<&str>,
    ) -> ApiResult<LxcSnapshotRecord> {
        let ct = self.get_stored(id).await?;
        // ensure_safe_snapshot also rejects the reserved clone-base prefix.
        let tag = crate::services::kvm::ensure_safe_snapshot(name)?;
        // Reject a duplicate up front so a repeat capture is a clean 409.
        if self.list_snapshots(id).await?.iter().any(|s| s.name == tag) {
            return Err(AppError::conflict(format!(
                "a snapshot named {tag:?} already exists"
            )));
        }
        let full = format!("{0}@{tag}", ct.rootfs_dataset);
        if let Err(e) = command::run_ok("zfs", &["snapshot", &full]).await {
            // The pre-check narrows the window, but a concurrent request can still
            // win the race; surface that as a 409 rather than a 502.
            if crate::services::kvm::is_already_exists(&e) {
                return Err(AppError::conflict(format!(
                    "a snapshot named {tag:?} already exists"
                )));
            }
            return Err(e);
        }

        if let Some(desc) = description.map(str::trim).filter(|d| !d.is_empty()) {
            // The description is read back from tab-delimited `zfs list -H` output,
            // so collapse any control whitespace to spaces before storing it, or a
            // value with a tab/newline would corrupt that parse.
            let sanitized: String = desc
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect();
            let prop = format!("daygleve:description={}", sanitized.trim());
            // The snapshot is already captured; a failed annotation must not fail
            // the whole operation.
            let _ = command::run_ok("zfs", &["set", &prop, &full]).await;
        }

        self.list_snapshots(id)
            .await?
            .into_iter()
            .find(|s| s.name == tag)
            .ok_or_else(|| AppError::internal("snapshot created but could not be read back"))
    }

    /// Roll the container's rootfs back to the named snapshot. Destructive of any
    /// newer snapshots (`zfs rollback -r`) and only allowed while the container is
    /// stopped, or a live rollback would corrupt the running rootfs.
    pub async fn rollback_snapshot(&self, id: &str, name: &str) -> ApiResult<()> {
        let ct = self.get_stored(id).await?;
        let tag = crate::services::kvm::ensure_safe_snapshot(name)?;
        self.require_stopped(&ct, "rolling back a snapshot").await?;
        // Confirm the snapshot exists before the destructive call, so a missing
        // snapshot is a clean 404 rather than a 502 from `zfs rollback`.
        if !self.snapshot_exists(&ct.rootfs_dataset, tag).await? {
            return Err(AppError::not_found(format!("no snapshot named {tag:?}")));
        }
        let target = format!("{0}@{tag}", ct.rootfs_dataset);
        command::run_ok("zfs", &["rollback", "-r", &target]).await?;
        Ok(())
    }

    /// Delete a snapshot.
    pub async fn delete_snapshot(&self, id: &str, name: &str) -> ApiResult<()> {
        let ct = self.get_stored(id).await?;
        let tag = crate::services::kvm::ensure_safe_snapshot(name)?;
        // A missing snapshot is a 404, not a 502 from `zfs destroy`.
        if !self.snapshot_exists(&ct.rootfs_dataset, tag).await? {
            return Err(AppError::not_found(format!("no snapshot named {tag:?}")));
        }
        let target = format!("{0}@{tag}", ct.rootfs_dataset);
        command::run_ok("zfs", &["destroy", &target]).await?;
        Ok(())
    }

    /// List snapshots for a container, read straight from ZFS (the source of
    /// truth) so `used_bytes` and `created_at` reflect the real dataset and each
    /// snapshot keeps a stable id across calls.
    pub async fn list_snapshots(&self, id: &str) -> ApiResult<Vec<LxcSnapshotRecord>> {
        let ct = self.get_stored(id).await?;
        let prefix = format!("{0}@", ct.rootfs_dataset);
        let out = match command::run_optional(
            "zfs",
            &[
                "list",
                "-t",
                "snapshot",
                "-Hp",
                "-o",
                "name,used,creation,daygleve:description",
                "-d",
                "1",
                &ct.rootfs_dataset,
            ],
        )
        .await
        {
            Ok(Some(o)) => o,
            Ok(None) => return Ok(Vec::new()),
            Err(e) if crate::services::kvm::is_missing_dataset(&e) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut snapshots = Vec::new();
        for line in out.lines().filter(|l| !l.trim().is_empty()) {
            let mut cols = line.split('\t');
            let full = cols.next().unwrap_or_default();
            let name = match full.strip_prefix(&prefix) {
                Some(n) if !n.is_empty() => n,
                _ => continue,
            };
            // `-p` always emits numeric used/creation; skip a row that doesn't
            // parse rather than fabricate a 0-byte / epoch-0 entry.
            let (Some(used_bytes), Some(creation)) = (
                cols.next().and_then(|s| s.parse::<u64>().ok()),
                cols.next().and_then(|s| s.parse::<i64>().ok()),
            ) else {
                continue;
            };
            let desc = cols.next().unwrap_or("-");
            let description = (desc != "-" && !desc.is_empty()).then(|| desc.to_string());
            snapshots.push(LxcSnapshotRecord {
                id: snapshot_id(&ct.id, name),
                name: name.to_string(),
                container_id: ct.id.clone(),
                dataset: ct.rootfs_dataset.clone(),
                used_bytes,
                description,
                created_at: crate::services::kvm::ts_from_unix(creation),
            });
        }
        Ok(snapshots)
    }

    /// Whether `dataset@tag` exists, so a caller can reject a missing snapshot
    /// before a destructive `zfs` call. A missing `zfs` binary is an operational
    /// error on these endpoints (502), not a 404.
    async fn snapshot_exists(&self, dataset: &str, tag: &str) -> ApiResult<bool> {
        let target = format!("{dataset}@{tag}");
        match command::run_optional(
            "zfs",
            &["list", "-H", "-o", "name", "-t", "snapshot", &target],
        )
        .await
        {
            Ok(Some(o)) if !o.trim().is_empty() => Ok(true),
            // Empty output, or a "does not exist" error: the snapshot is absent.
            Ok(Some(_)) => Ok(false),
            Err(e) if crate::services::kvm::is_missing_dataset(&e) => Ok(false),
            Ok(None) => Err(AppError::hypervisor(
                "zfs is not installed; cannot manage snapshots",
            )),
            Err(e) => Err(e),
        }
    }

    /// Whether the container is stopped, so a destructive rollback can be
    /// rejected while it is running/frozen. `None` (state indeterminate — e.g. a
    /// dev host without `lxc`) is treated as permissible, matching the VM path.
    async fn require_stopped(&self, ct: &Lxc, action: &str) -> ApiResult<()> {
        match self.live_state(&ct.name).await {
            Some(LxcState::Stopped) | None => Ok(()),
            Some(_) => Err(AppError::conflict(format!(
                "stop the container before {action}"
            ))),
        }
    }

    /// Write CPU/memory cgroup limits and vet the bridge name.
    ///
    /// Config
    async fn write_config(
        &self,
        name: &str,
        vcpus: u32,
        memory_mib: u64,
        networks: &[LxcNetwork],
        mounts: &[LxcMount],
    ) -> ApiResult<()> {
        let mut block = String::from("\n# --- DaygleVE limits & networking ---\n");
        block.push_str(&format!(
            "lxc.cgroup2.memory.max = {}\n",
            memory_mib * 1024 * 1024
        ));
        block.push_str(&format!(
            "lxc.cgroup2.cpu.max = {} 100000\n",
            vcpus as u64 * 100_000
        ));
        for (i, net) in networks.iter().enumerate() {
            block.push_str(&format!("lxc.net.{i}.type = veth\n"));
            block.push_str(&format!("lxc.net.{i}.link = {}\n", net.bridge));
            block.push_str(&format!("lxc.net.{i}.flags = up\n"));
            if let Some(vlan) = net.vlan {
                block.push_str(&format!("lxc.net.{i}.vlan.id = {vlan}\n"));
            }
            if let Some(ip) = &net.ip {
                block.push_str(&format!("lxc.net.{i}.ipv4.address = {ip}\n"));
            }
        }
        for mount in mounts {
            // Re-validate at render time (the same check create runs) so a
            // record that somehow carried an unsafe mount can't reach the config
            // writer. The destination is made relative to the container rootfs.
            validate_mount(mount)?;
            block.push_str(&mount_entry_line(mount));
        }

        command::append_lxc_config(name, &block).await
    }
}

/// Render one validated bind mount as an `lxc.mount.entry` line. The container
/// destination is relative to the rootfs (LXC requirement), so the leading `/`
/// is stripped; `create=dir` makes the mountpoint if it does not exist.
fn mount_entry_line(mount: &LxcMount) -> String {
    let dest_rel = mount.destination.trim_start_matches('/');
    let opts = if mount.read_only {
        "bind,ro,create=dir"
    } else {
        "bind,rw,create=dir"
    };
    format!(
        "lxc.mount.entry = {} {} none {} 0 0\n",
        mount.source.trim(),
        dest_rel,
        opts
    )
}

/// Validate a container bind mount before it is written into the config. Bind
/// mounting host paths into a container is a privileged capability, so the paths
/// are held to strict rules: both absolute, no `..` traversal, no whitespace or
/// control characters (an `lxc.mount.entry` is whitespace-delimited, so a space
/// would split a path into extra fields). Mirrors the broker's independent
/// `lxc.mount.entry` check.
fn validate_mount(mount: &LxcMount) -> ApiResult<()> {
    let safe_abs = |p: &str, field: &str| -> ApiResult<()> {
        if !p.starts_with('/') {
            return Err(AppError::validation(format!(
                "{field} must be an absolute path"
            )));
        }
        if p.split('/').any(|c| c == "..") {
            return Err(AppError::validation(format!(
                "{field} must not contain `..`"
            )));
        }
        if p.len() > 1024 || p.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(AppError::validation(format!(
                "{field} contains whitespace, control characters, or is too long"
            )));
        }
        Ok(())
    };
    safe_abs(mount.source.trim(), "mount.source")?;
    safe_abs(mount.destination.trim(), "mount.destination")?;
    // A destination of exactly `/` would strip to an empty container path.
    if mount.destination.trim().trim_start_matches('/').is_empty() {
        return Err(AppError::validation(
            "mount.destination must not be the container root",
        ));
    }
    Ok(())
}

/// A stable, deterministic id for a container snapshot, so the same
/// `container@name` snapshot keeps one id across `list` calls (the UI keys on
/// it). Derived as a UUIDv5 over `container_id@name`.
fn snapshot_id(container_id: &str, name: &str) -> String {
    uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_OID,
        format!("{container_id}@{name}").as_bytes(),
    )
    .to_string()
}

fn summary_of(ct: &Lxc) -> LxcSummary {
    LxcSummary {
        id: ct.id.clone(),
        name: ct.name.clone(),
        state: ct.state,
        vcpus: ct.vcpus,
        memory_mib: ct.memory_mib,
        created_at: ct.created_at.clone(),
    }
}

fn map_lxc_state(s: &str) -> LxcState {
    match s.trim().to_ascii_uppercase().as_str() {
        "RUNNING" => LxcState::Running,
        "STOPPED" => LxcState::Stopped,
        "FROZEN" => LxcState::Frozen,
        "STARTING" | "STOPPING" | "ABORTING" | "FREEZING" | "THAWED" => LxcState::Transitioning,
        _ => LxcState::Stopped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mount(source: &str, destination: &str, read_only: bool) -> LxcMount {
        LxcMount {
            source: source.to_string(),
            destination: destination.to_string(),
            read_only,
        }
    }

    #[test]
    fn valid_mounts_are_accepted_and_bad_ones_rejected() {
        assert!(validate_mount(&mount("/srv/data", "/data", true)).is_ok());
        assert!(validate_mount(&mount("/srv/data", "/mnt/data", false)).is_ok());
        // Relative source, `..` traversal, whitespace, and container-root dest.
        assert!(validate_mount(&mount("srv/data", "/data", true)).is_err());
        assert!(validate_mount(&mount("/srv/../etc", "/data", true)).is_err());
        assert!(validate_mount(&mount("/srv/data", "/a/../..", true)).is_err());
        assert!(validate_mount(&mount("/srv da ta", "/data", true)).is_err());
        assert!(validate_mount(&mount("/srv/data", "/", true)).is_err());
    }

    #[test]
    fn rendered_mount_entry_relativizes_dest_and_passes_the_broker() {
        let ro = mount_entry_line(&mount("/srv/data", "/data", true));
        assert_eq!(
            ro,
            "lxc.mount.entry = /srv/data data none bind,ro,create=dir 0 0\n"
        );
        let rw = mount_entry_line(&mount("/srv/data", "/mnt/data", false));
        assert_eq!(
            rw,
            "lxc.mount.entry = /srv/data mnt/data none bind,rw,create=dir 0 0\n"
        );
        // The line the service renders must satisfy the broker's independent
        // config-block validator (defense in depth).
        assert!(crate::broker::validate_lxc_config_block(&ro).is_ok());
        assert!(crate::broker::validate_lxc_config_block(&rw).is_ok());
    }
}
