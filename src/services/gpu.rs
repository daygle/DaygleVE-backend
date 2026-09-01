//! GPU passthrough service: host GPU inventory and vfio-pci binding.
//!
//! TODO(gpu): enumerate PCI devices under `/sys/bus/pci`, resolve IOMMU groups
//! and manage `vfio-pci` driver binding.

use daygleve_schema::gpu::{BindGpuRequest, GpuDevice};

use crate::error::{ApiResult, AppError};

pub struct GpuService;

impl GpuService {
    pub fn new() -> Self {
        Self
    }

    pub fn list(&self) -> Vec<GpuDevice> {
        // TODO(gpu): scan `/sys/bus/pci/devices` for display controllers.
        Vec::new()
    }

    pub fn bind(&self, pci_address: &str, _req: BindGpuRequest) -> ApiResult<GpuDevice> {
        if pci_address.trim().is_empty() {
            return Err(AppError::validation("pci_address must not be empty"));
        }
        // TODO(gpu): unbind the host driver and bind vfio-pci for the whole
        // IOMMU group.
        Err(AppError::hypervisor(
            "GPU binding not yet implemented on this node",
        ))
    }
}
