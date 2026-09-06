//! LXC container lifecycle service.
//!
//! Drives the `lxc-*` tooling with a ZFS-backed rootfs (`lxc-create -B zfs`).
//! As with VMs, LXC persists the container config/rootfs itself and DaygleVE
//! keeps a sidecar record of the structured `Lxc`, overlaying live state from
//! `lxc-info` at read time. CPU/memory limits and veth networking are written
//! into the container config at create time.
//!
//! This is the least host-portable of the services: it depends on the
//! `download` template server and a ZFS-capable `lxc`. Templates are given as
//! `<dist>-<release>` (e.g. `debian-bookworm`).

use std::sync::Arc;

use daygleve_schema::lxc::{
    CreateLxcRequest, Lxc, LxcNetwork, LxcPowerAction, LxcState, LxcSummary, UpdateLxcRequest,
};

use daygleve_schema::lxc_snapshot::LxcSnapshotRecord;

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::store::JsonStore;
use crate::services::{
    command, ensure_safe_cidr, ensure_safe_id, ensure_safe_zfs_dataset, new_id, now_ts,
};

pub struct LxcService {
    store: JsonStore,
    config: Arc<Config>,
}

impl LxcService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            store: JsonStore::new(&config.state_dir, "containers"),
            config,
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

        ensure_safe_zfs_dataset(&self.config.default_pool)?;
        let zfsroot = format!("{}/lxc", self.config.default_pool);
        let rootfs_dataset = format!("{zfsroot}/{}", req.name);

        // Create the container with a ZFS-backed rootfs from a download image.
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
            .write_config(&req.name, req.vcpus, req.memory_mib, &req.networks)
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
        self.write_config(&ct.name, ct.vcpus, ct.memory_mib, &ct.networks)
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

        command::append_lxc_config(name, &block).await
    }
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
