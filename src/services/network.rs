//! Linux networking service: bridges and VLANs.
//!
//! TODO(net): drive `ip`/`bridge` (or rtnetlink) and persist config. Scaffold
//! keeps bridges/VLANs in memory.

use std::sync::RwLock;

use daygleve_schema::network::{Bridge, CreateBridgeRequest, CreateVlanRequest, LinkState, Vlan};

use crate::error::{ApiResult, AppError};
use crate::services::{new_id, now_ts};

pub struct NetworkService {
    bridges: RwLock<Vec<Bridge>>,
    vlans: RwLock<Vec<Vlan>>,
}

impl NetworkService {
    pub fn new() -> Self {
        Self {
            bridges: RwLock::new(Vec::new()),
            vlans: RwLock::new(Vec::new()),
        }
    }

    pub fn list_bridges(&self) -> Vec<Bridge> {
        self.bridges.read().expect("bridge lock").clone()
    }

    pub fn create_bridge(&self, req: CreateBridgeRequest) -> ApiResult<Bridge> {
        if req.name.trim().is_empty() {
            return Err(AppError::validation("bridge name must not be empty"));
        }
        // TODO(net): `ip link add <name> type bridge` + enslave ports.
        let bridge = Bridge {
            id: new_id(),
            name: req.name,
            state: LinkState::Up,
            ports: req.ports,
            vlan_aware: req.vlan_aware,
            address: req.address,
            mtu: req.mtu.unwrap_or(1500),
            created_at: now_ts(),
        };
        self.bridges
            .write()
            .expect("bridge lock")
            .push(bridge.clone());
        Ok(bridge)
    }

    pub fn list_vlans(&self) -> Vec<Vlan> {
        self.vlans.read().expect("vlan lock").clone()
    }

    pub fn create_vlan(&self, req: CreateVlanRequest) -> ApiResult<Vlan> {
        if !(1..=4094).contains(&req.tag) {
            return Err(AppError::validation("vlan tag must be in 1..=4094"));
        }
        // TODO(net): `bridge vlan add vid <tag> dev <bridge>`.
        let vlan = Vlan {
            id: new_id(),
            bridge: req.bridge,
            tag: req.tag,
            name: req.name,
        };
        self.vlans.write().expect("vlan lock").push(vlan.clone());
        Ok(vlan)
    }
}
