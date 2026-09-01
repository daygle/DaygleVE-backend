//! KVM/QEMU virtual-machine lifecycle service.
//!
//! TODO(hypervisor): back these operations with libvirt (or a direct QEMU
//! monitor). For now an in-memory registry lets the REST surface be exercised.

use std::collections::HashMap;
use std::sync::RwLock;

use daygleve_schema::common::ResourceId;
use daygleve_schema::vm::{
    ConsoleTicket, CreateVmRequest, UpdateVmRequest, Vm, VmPowerAction, VmState, VmSummary,
};

use crate::error::{ApiResult, AppError};
use crate::services::{new_id, now_ts};

/// In-memory VM registry. Replace the map with a libvirt connection handle.
pub struct KvmService {
    vms: RwLock<HashMap<ResourceId, Vm>>,
}

impl KvmService {
    pub fn new() -> Self {
        Self {
            vms: RwLock::new(HashMap::new()),
        }
    }

    pub fn list(&self) -> Vec<VmSummary> {
        let vms = self.vms.read().expect("vm lock");
        vms.values().map(summary_of).collect()
    }

    pub fn get(&self, id: &str) -> ApiResult<Vm> {
        self.vms
            .read()
            .expect("vm lock")
            .get(id)
            .cloned()
            .ok_or_else(|| AppError::not_found(format!("vm {id} not found")))
    }

    pub fn create(&self, req: CreateVmRequest) -> ApiResult<Vm> {
        if req.vcpus == 0 {
            return Err(AppError::validation("vcpus must be >= 1"));
        }
        // TODO(hypervisor): define the libvirt domain XML and provision disks.
        let vm = Vm {
            id: new_id(),
            name: req.name,
            state: if req.start {
                VmState::Running
            } else {
                VmState::Stopped
            },
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
        self.vms
            .write()
            .expect("vm lock")
            .insert(vm.id.clone(), vm.clone());
        Ok(vm)
    }

    pub fn update(&self, id: &str, req: UpdateVmRequest) -> ApiResult<Vm> {
        let mut vms = self.vms.write().expect("vm lock");
        let vm = vms
            .get_mut(id)
            .ok_or_else(|| AppError::not_found(format!("vm {id} not found")))?;
        if let Some(name) = req.name {
            vm.name = name;
        }
        if let Some(vcpus) = req.vcpus {
            vm.vcpus = vcpus;
        }
        if let Some(mem) = req.memory_mib {
            vm.memory_mib = mem;
        }
        if req.description.is_some() {
            vm.description = req.description;
        }
        vm.updated_at = Some(now_ts());
        Ok(vm.clone())
    }

    pub fn delete(&self, id: &str) -> ApiResult<()> {
        self.vms
            .write()
            .expect("vm lock")
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| AppError::not_found(format!("vm {id} not found")))
    }

    pub fn power(&self, id: &str, action: VmPowerAction) -> ApiResult<Vm> {
        let mut vms = self.vms.write().expect("vm lock");
        let vm = vms
            .get_mut(id)
            .ok_or_else(|| AppError::not_found(format!("vm {id} not found")))?;
        // TODO(hypervisor): issue the corresponding libvirt lifecycle call.
        vm.state = match action {
            VmPowerAction::Start | VmPowerAction::Resume => VmState::Running,
            VmPowerAction::Shutdown | VmPowerAction::Stop => VmState::Stopped,
            VmPowerAction::Pause => VmState::Paused,
            VmPowerAction::Reboot | VmPowerAction::Reset => VmState::Running,
        };
        vm.updated_at = Some(now_ts());
        Ok(vm.clone())
    }

    pub fn console(&self, id: &str) -> ApiResult<ConsoleTicket> {
        // Ensure the VM exists before minting a ticket.
        let _ = self.get(id)?;
        // TODO(console): allocate a VNC port and register a one-time ticket
        // with the noVNC websocket proxy.
        Ok(ConsoleTicket {
            websocket_path: format!("/api/v1/vms/{id}/console/ws"),
            ticket: new_id(),
            expires_at: now_ts(),
        })
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
