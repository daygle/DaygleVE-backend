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
use crate::services::{command, new_id, now_ts};

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

        // Create the bridge device (optionally VLAN-aware).
        let mut add = vec!["link", "add", "name", &req.name, "type", "bridge"];
        if req.vlan_aware {
            add.extend_from_slice(&["vlan_filtering", "1"]);
        }
        command::run_ok("ip", &add).await?;

        // Enslave ports and bring them up.
        for port in &req.ports {
            command::run_ok("ip", &["link", "set", port, "master", &req.name]).await?;
            command::run_ok("ip", &["link", "set", port, "up"]).await?;
        }

        if let Some(mtu) = req.mtu {
            let mtu = mtu.to_string();
            command::run_ok("ip", &["link", "set", &req.name, "mtu", &mtu]).await?;
        }
        if let Some(addr) = &req.address {
            command::run_ok("ip", &["addr", "add", addr, "dev", &req.name]).await?;
        }
        command::run_ok("ip", &["link", "set", &req.name, "up"]).await?;

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
        self.bridges.put(&bridge.name, &bridge).await?;
        Ok(bridge)
    }

    pub async fn list_vlans(&self) -> ApiResult<Vec<Vlan>> {
        self.vlans.list().await
    }

    pub async fn create_vlan(&self, req: CreateVlanRequest) -> ApiResult<Vlan> {
        if !(1..=4094).contains(&req.tag) {
            return Err(AppError::validation("vlan tag must be in 1..=4094"));
        }
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
        self.vlans.put(&vlan.id, &vlan).await?;
        Ok(vlan)
    }

    /// Interfaces enslaved to `bridge` (`ip -j link show master <bridge>`).
    async fn bridge_ports(&self, bridge: &str) -> ApiResult<Vec<String>> {
        let json =
            match command::run_optional("ip", &["-j", "link", "show", "master", bridge]).await? {
                Some(json) => json,
                None => return Ok(Vec::new()),
            };
        let links: Vec<Value> = serde_json::from_str(json.trim()).unwrap_or_default();
        Ok(links
            .into_iter()
            .filter_map(|l| l["ifname"].as_str().map(str::to_string))
            .collect())
    }

    /// First IPv4 address on `bridge` in CIDR form, if any.
    async fn bridge_address(&self, bridge: &str) -> ApiResult<Option<String>> {
        let json = match command::run_optional("ip", &["-j", "addr", "show", "dev", bridge]).await?
        {
            Some(json) => json,
            None => return Ok(None),
        };
        let entries: Vec<Value> = serde_json::from_str(json.trim()).unwrap_or_default();
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
