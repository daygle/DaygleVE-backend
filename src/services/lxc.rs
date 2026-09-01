//! LXC container lifecycle service.
//!
//! TODO(lxc): back these operations with the LXC API / `lxc-*` tooling and a
//! ZFS-backed rootfs. In-memory for the scaffold.

use std::collections::HashMap;
use std::sync::RwLock;

use daygleve_schema::common::ResourceId;
use daygleve_schema::lxc::{
    CreateLxcRequest, Lxc, LxcPowerAction, LxcState, LxcSummary, UpdateLxcRequest,
};

use crate::error::{ApiResult, AppError};
use crate::services::{new_id, now_ts};

pub struct LxcService {
    containers: RwLock<HashMap<ResourceId, Lxc>>,
}

impl LxcService {
    pub fn new() -> Self {
        Self {
            containers: RwLock::new(HashMap::new()),
        }
    }

    pub fn list(&self) -> Vec<LxcSummary> {
        self.containers
            .read()
            .expect("lxc lock")
            .values()
            .map(summary_of)
            .collect()
    }

    pub fn get(&self, id: &str) -> ApiResult<Lxc> {
        self.containers
            .read()
            .expect("lxc lock")
            .get(id)
            .cloned()
            .ok_or_else(|| AppError::not_found(format!("container {id} not found")))
    }

    pub fn create(&self, req: CreateLxcRequest) -> ApiResult<Lxc> {
        if req.vcpus == 0 {
            return Err(AppError::validation("vcpus must be >= 1"));
        }
        // TODO(lxc): create the ZFS rootfs from `req.template` and write config.
        let ct = Lxc {
            id: new_id(),
            name: req.name,
            state: if req.start {
                LxcState::Running
            } else {
                LxcState::Stopped
            },
            template: req.template,
            rootfs_dataset: String::new(), // TODO: set to provisioned dataset
            vcpus: req.vcpus,
            memory_mib: req.memory_mib,
            networks: req.networks,
            unprivileged: req.unprivileged,
            description: req.description,
            created_at: now_ts(),
            updated_at: None,
        };
        self.containers
            .write()
            .expect("lxc lock")
            .insert(ct.id.clone(), ct.clone());
        Ok(ct)
    }

    pub fn update(&self, id: &str, req: UpdateLxcRequest) -> ApiResult<Lxc> {
        let mut cts = self.containers.write().expect("lxc lock");
        let ct = cts
            .get_mut(id)
            .ok_or_else(|| AppError::not_found(format!("container {id} not found")))?;
        if let Some(name) = req.name {
            ct.name = name;
        }
        if let Some(vcpus) = req.vcpus {
            ct.vcpus = vcpus;
        }
        if let Some(mem) = req.memory_mib {
            ct.memory_mib = mem;
        }
        if req.description.is_some() {
            ct.description = req.description;
        }
        ct.updated_at = Some(now_ts());
        Ok(ct.clone())
    }

    pub fn delete(&self, id: &str) -> ApiResult<()> {
        self.containers
            .write()
            .expect("lxc lock")
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| AppError::not_found(format!("container {id} not found")))
    }

    pub fn power(&self, id: &str, action: LxcPowerAction) -> ApiResult<Lxc> {
        let mut cts = self.containers.write().expect("lxc lock");
        let ct = cts
            .get_mut(id)
            .ok_or_else(|| AppError::not_found(format!("container {id} not found")))?;
        // TODO(lxc): issue the corresponding lxc lifecycle call.
        ct.state = match action {
            LxcPowerAction::Start | LxcPowerAction::Unfreeze | LxcPowerAction::Restart => {
                LxcState::Running
            }
            LxcPowerAction::Stop => LxcState::Stopped,
            LxcPowerAction::Freeze => LxcState::Frozen,
        };
        ct.updated_at = Some(now_ts());
        Ok(ct.clone())
    }
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
