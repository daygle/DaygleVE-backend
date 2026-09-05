//! Linux networking service: bridges and VLANs.
//!
//! Bridges are created and inspected live via `ip`/`bridge` (iproute2's `-j`
//! JSON output is parsed for state). DaygleVE keeps a small sidecar record per
//! bridge/VLAN so it can report a creation time and list configured VLANs
//! (which `bridge vlan show` does not attribute cleanly). Reboot-persistent
//! network config (ifupdown2) is a follow-up; bridges are applied live.

use std::collections::HashMap;
use std::sync::Arc;

use daygleve_schema::network::{Bridge, CreateBridgeRequest, CreateVlanRequest, LinkState, Vlan};
use serde_json::Value;

use crate::config::Config;
use crate::error::{ApiResult, AppError};
use crate::services::store::JsonStore;
use crate::services::{command, ensure_safe_cidr, new_id, now_ts};

pub struct NetworkService {
    bridges: JsonStore,
    vlans: JsonStore,
}

impl NetworkService {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            bridges: JsonStore::new(&config.state_dir, "bridges"),
            vlans: JsonStore::new(&config.state_dir, "vlans"),
        }
    }

    pub async fn list_bridges(&self) -> ApiResult<Vec<Bridge>> {
        // created_at (and other intent) comes from our sidecar records.
        let stored: Vec<Bridge> = self.bridges.list().await?;
        let meta: HashMap<String, Bridge> =
            stored.into_iter().map(|b| (b.name.clone(), b)).collect();

        let json =
            match command::run_optional("ip", &["-d", "-j", "link", "show", "type", "bridge"])
                .await?
            {
                Some(json) => json,
                // No iproute2: fall back to whatever we have recorded.
                None => return Ok(meta.into_values().collect()),
            };

        let links: Vec<Value> = serde_json::from_str(json.trim())
            .map_err(|e| AppError::internal(format!("parse `ip -j`: {e}")))?;

        let mut out = Vec::new();
        for link in links {
            let name = link["ifname"].as_str().unwrap_or_default().to_string();
            if name.is_empty() {
                continue;
            }
            let recorded = meta.get(&name);
            out.push(Bridge {
                id: name.clone(),
                state: link_state(link["operstate"].as_str().unwrap_or("UNKNOWN")),
                ports: self.bridge_ports(&name).await?,
                vlan_aware: link
                    .pointer("/linkinfo/info_data/vlan_filtering")
                    .and_then(Value::as_i64)
                    .map(|v| v != 0)
                    .or_else(|| recorded.map(|b| b.vlan_aware))
                    .unwrap_or(false),
                address: self.bridge_address(&name).await?,
                mtu: link["mtu"].as_u64().unwrap_or(1500) as u32,
                created_at: recorded.map(|b| b.created_at.clone()).unwrap_or_default(),
                name,
            });
        }
        Ok(out)
    }

    pub async fn create_bridge(&self, req: CreateBridgeRequest) -> ApiResult<Bridge> {
        if req.name.trim().is_empty() {
            return Err(AppError::validation("bridge name must not be empty"));
        }
        // Validate before any host change so we can't create the bridge via
        // `ip` and then fail to persist its record (the name is also its id).
        crate::services::ensure_safe_id(&req.name)?;

        // Validate every port name before any host change so a name that could
        // be misparsed as an `ip` flag is rejected up front.
        for port in &req.ports {
            crate::services::ensure_safe_id(port)?;
        }
        if let Some(address) = req.address.as_deref() {
            ensure_safe_cidr(address, "bridge.address")?;
        }
        if let Some(mtu) = req.mtu {
            if !(576..=65_535).contains(&mtu) {
                return Err(AppError::validation("bridge MTU must be in 576..=65535"));
            }
        }

        // Create the bridge device (optionally VLAN-aware).
        let mut add = vec!["link", "add", "name", &req.name, "type", "bridge"];
        if req.vlan_aware {
            add.extend_from_slice(&["vlan_filtering", "1"]);
        }
        command::run_ok("ip", &add).await?;

        // Configure the bridge (ports, MTU, address, up). On ANY failure after
        // the device was created, roll it back so the host keeps no orphan
        // bridge without a matching DaygleVE record.
        if let Err(e) = self.configure_bridge(&req).await {
            let _ = command::run_optional("ip", &["link", "del", "dev", &req.name]).await;
            return Err(e);
        }

        let bridge = Bridge {
            id: req.name.clone(),
            name: req.name.clone(),
            state: LinkState::Up,
            ports: req.ports,
            vlan_aware: req.vlan_aware,
            address: req.address,
            mtu: req.mtu.unwrap_or(1500),
            created_at: now_ts(),
        };
        // Same rollback if persisting the record fails.
        if let Err(e) = self.bridges.put(&bridge.name, &bridge).await {
            let _ = command::run_optional("ip", &["link", "del", "dev", &bridge.name]).await;
            return Err(e);
        }
        Ok(bridge)
    }

    /// Enslave ports and apply MTU/address, then bring the bridge up. Explicit
    /// `dev` keywords keep a leading-dash name from being read as an option.
    async fn configure_bridge(&self, req: &CreateBridgeRequest) -> ApiResult<()> {
        for port in &req.ports {
            command::run_ok("ip", &["link", "set", "dev", port, "master", &req.name]).await?;
            command::run_ok("ip", &["link", "set", "dev", port, "up"]).await?;
        }
        if let Some(mtu) = req.mtu {
            let mtu = mtu.to_string();
            command::run_ok("ip", &["link", "set", "dev", &req.name, "mtu", &mtu]).await?;
        }
        if let Some(addr) = &req.address {
            command::run_ok("ip", &["addr", "add", addr, "dev", &req.name]).await?;
        }
        command::run_ok("ip", &["link", "set", "dev", &req.name, "up"]).await
    }

    /// Recreate a persisted bridge that is missing from the host. This is
    /// non-destructive and does not adopt or delete unmanaged interfaces.
    pub async fn repair_missing_from_host(&self, name: &str) -> ApiResult<()> {
        let bridge: Bridge = self
            .bridges
            .get(name)
            .await?
            .ok_or_else(|| AppError::not_found("bridge record not found"))?;
        crate::services::ensure_safe_id(&bridge.name)?;
        let add = [
            "link",
            "add",
            "name",
            bridge.name.as_str(),
            "type",
            "bridge",
        ];
        command::run_ok("ip", &add).await?;
        let req = CreateBridgeRequest {
            name: bridge.name.clone(),
            ports: bridge.ports.clone(),
            vlan_aware: bridge.vlan_aware,
            address: bridge.address.clone(),
            mtu: Some(bridge.mtu),
        };
        if let Err(error) = self.configure_bridge(&req).await {
            let _ = command::run_optional("ip", &["link", "del", "dev", &bridge.name]).await;
            return Err(error);
        }
        Ok(())
    }

    pub async fn list_vlans(&self) -> ApiResult<Vec<Vlan>> {
        self.vlans.list().await
    }

    pub async fn create_vlan(&self, req: CreateVlanRequest) -> ApiResult<Vlan> {
        if !(1..=4094).contains(&req.tag) {
            return Err(AppError::validation("vlan tag must be in 1..=4094"));
        }
        // The bridge name goes to the `bridge` CLI; reject flag-like values.
        crate::services::ensure_safe_id(&req.bridge)?;
        let tag = req.tag.to_string();
        // Register the VLAN on the (VLAN-aware) bridge itself.
        command::run_ok(
            "bridge",
            &["vlan", "add", "vid", &tag, "dev", &req.bridge, "self"],
        )
        .await?;

        let vlan = Vlan {
            id: new_id(),
            bridge: req.bridge,
            tag: req.tag,
            name: req.name,
        };
        // Roll the host VLAN back if we can't persist its record, so the
        // configured VLAN and DaygleVE state don't diverge.
        if let Err(e) = self.vlans.put(&vlan.id, &vlan).await {
            let _ = command::run_optional(
                "bridge",
                &["vlan", "del", "vid", &tag, "dev", &vlan.bridge, "self"],
            )
            .await;
            return Err(e);
        }
        Ok(vlan)
    }

    /// Interfaces enslaved to `bridge` (`ip -j link show master <bridge>`).
    async fn bridge_ports(&self, bridge: &str) -> ApiResult<Vec<String>> {
        let json =
            match command::run_optional("ip", &["-j", "link", "show", "master", bridge]).await? {
                Some(json) => json,
                None => return Ok(Vec::new()),
            };
        let links: Vec<Value> = serde_json::from_str(json.trim())
            .map_err(|e| AppError::internal(format!("parse `ip -j link show master`: {e}")))?;
        Ok(links
            .into_iter()
            .filter_map(|l| l["ifname"].as_str().map(str::to_string))
            .collect())
    }

    /// Compare persisted bridge/VLAN records to live host state, returning findings.
    ///
    /// Read-only: never modifies the host or the store.
    pub async fn reconcile_with_host(&self) -> ApiResult<(Vec<String>, Vec<String>)> {
        let mut missing_in_host = Vec::new();
        let mut missing_in_store = Vec::new();

        // Bridges recorded but not present on the host.
        let stored_bridges: Vec<daygleve_schema::network::Bridge> = self.bridges.list().await?;
        let live_bridges = self.list_bridges().await?;
        let live_bridge_names: std::collections::HashSet<&str> =
            live_bridges.iter().map(|b| b.name.as_str()).collect();
        for bridge in &stored_bridges {
            if !live_bridge_names.contains(bridge.name.as_str()) {
                missing_in_host.push(bridge.name.clone());
            }
        }

        // Bridges present on the host but not recorded. The caller quarantines
        // these names; adoption is an explicit operator decision.
        let stored_names: std::collections::HashSet<&str> = stored_bridges
            .iter()
            .map(|bridge| bridge.name.as_str())
            .collect();
        for bridge in live_bridges {
            if !stored_names.contains(bridge.name.as_str()) {
                missing_in_store.push(bridge.name.clone());
            }
        }

        // VLANs recorded but not present (best-effort: check via bridge vlan show).
        let stored_vlans = self.vlans.list().await?;
        for vlan in stored_vlans {
            if let Ok(Some(result)) = self.vlan_exists_on_host(&vlan).await {
                if !result {
                    missing_in_host.push(format!("vlan:{}", vlan.id));
                }
            }
            // Don't fail the whole reconciliation for a single VLAN check failure.
        }

        Ok((missing_in_host, missing_in_store))
    }

    /// Adopt a live bridge into the DaygleVE inventory after explicit review.
    /// Existing host ports and addresses are recorded as observed state; no
    /// host mutation is performed.
    pub async fn adopt_bridge(&self, name: &str) -> ApiResult<Bridge> {
        crate::services::ensure_safe_id(name)?;
        let bridge = self
            .list_bridges()
            .await?
            .into_iter()
            .find(|bridge| bridge.name == name)
            .ok_or_else(|| AppError::not_found("bridge no longer exists on the host"))?;
        self.bridges.put(&bridge.id, &bridge).await?;
        Ok(bridge)
    }

    /// Recreate a persisted VLAN registration on the host. This is the only
    /// supported automatic VLAN repair and is non-destructive.
    pub async fn repair_vlan_from_host(&self, id: &str) -> ApiResult<()> {
        let vlan: Vlan = self
            .vlans
            .get(id)
            .await?
            .ok_or_else(|| AppError::not_found("VLAN record not found"))?;
        crate::services::ensure_safe_id(&vlan.bridge)?;
        let tag = vlan.tag.to_string();
        command::run_ok(
            "bridge",
            &["vlan", "add", "vid", &tag, "dev", &vlan.bridge, "self"],
        )
        .await
    }

    /// Check whether a VLAN exists on the host via `bridge vlan show`.
    async fn vlan_exists_on_host(
        &self,
        vlan: &daygleve_schema::network::Vlan,
    ) -> ApiResult<Option<bool>> {
        match command::run_optional("bridge", &["vlan", "show", "dev", &vlan.bridge]).await {
            Ok(Some(out)) => {
                let exists = out
                    .lines()
                    .any(|line| line.contains(&format!("vid {}", vlan.tag)));
                Ok(Some(exists))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// First IPv4 address on `bridge` in CIDR form, if any.
    async fn bridge_address(&self, bridge: &str) -> ApiResult<Option<String>> {
        let json = match command::run_optional("ip", &["-j", "addr", "show", "dev", bridge]).await?
        {
            Some(json) => json,
            None => return Ok(None),
        };
        let entries: Vec<Value> = serde_json::from_str(json.trim())
            .map_err(|e| AppError::internal(format!("parse `ip -j addr show`: {e}")))?;
        for entry in entries {
            if let Some(addrs) = entry["addr_info"].as_array() {
                for a in addrs {
                    if a["family"].as_str() == Some("inet") {
                        if let (Some(local), Some(prefix)) =
                            (a["local"].as_str(), a["prefixlen"].as_u64())
                        {
                            return Ok(Some(format!("{local}/{prefix}")));
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

fn link_state(operstate: &str) -> LinkState {
    match operstate.to_ascii_uppercase().as_str() {
        "UP" => LinkState::Up,
        "DOWN" => LinkState::Down,
        _ => LinkState::Unknown,
    }
}
