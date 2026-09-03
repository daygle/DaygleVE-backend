//! GPU passthrough service: host GPU inventory and vfio-pci binding.
//!
//! Enumerates PCI display controllers under `/sys/bus/pci/devices`, resolves
//! their IOMMU group and current driver, and (on bind) rebinds every function
//! in the group to `vfio-pci` so the group can be handed to a guest. All of
//! this is plain sysfs I/O; binding requires the process to run as root and the
//! `vfio-pci` module to be loaded.

use std::path::{Path, PathBuf};

use daygleve_schema::gpu::{BindGpuRequest, GpuDevice};
use tokio::fs;

use crate::error::{ApiResult, AppError};

const PCI_DEVICES: &str = "/sys/bus/pci/devices";

pub struct GpuService;

impl GpuService {
    pub fn new() -> Self {
        Self
    }

    pub async fn list(&self) -> ApiResult<Vec<GpuDevice>> {
        let mut out = Vec::new();
        let mut rd = match fs::read_dir(PCI_DEVICES).await {
            Ok(rd) => rd,
            // No PCI sysfs (non-Linux/dev host): nothing to enumerate.
            Err(_) => return Ok(out),
        };
        while let Some(entry) = rd
            .next_entry()
            .await
            .map_err(|e| AppError::internal(format!("read_dir {PCI_DEVICES}: {e}")))?
        {
            let dir = entry.path();
            let class = read_trimmed(&dir.join("class")).await.unwrap_or_default();
            // PCI base class 0x03 == display controller (VGA/3D/other display).
            if !class.starts_with("0x03") {
                continue;
            }
            if let Some(dev) = read_gpu(&dir).await {
                out.push(dev);
            }
        }
        Ok(out)
    }

    pub async fn bind(&self, pci_address: &str, req: BindGpuRequest) -> ApiResult<GpuDevice> {
        if pci_address.trim().is_empty() {
            return Err(AppError::validation("pci_address must not be empty"));
        }
        let dir = PathBuf::from(PCI_DEVICES).join(pci_address);
        if fs::metadata(&dir).await.is_err() {
            return Err(AppError::not_found(format!(
                "PCI device {pci_address} not found"
            )));
        }

        // Rebind every function in the IOMMU group — a group is the smallest
        // unit that can be isolated and passed through.
        for addr in iommu_group_members(&dir).await? {
            bind_one(&addr, req.force).await?;
        }

        read_gpu(&PathBuf::from(PCI_DEVICES).join(pci_address))
            .await
            .ok_or_else(|| {
                AppError::hypervisor(format!("device {pci_address} unreadable after bind"))
            })
    }
}

/// Bind a single PCI function to `vfio-pci`.
async fn bind_one(addr: &str, force: bool) -> ApiResult<()> {
    let dir = PathBuf::from(PCI_DEVICES).join(addr);
    let current = current_driver(&dir).await;

    if let Some(driver) = &current {
        if driver == "vfio-pci" {
            return Ok(()); // already ours
        }
        if !force {
            return Err(AppError::conflict(format!(
                "{addr} is bound to host driver `{driver}`; retry with force to rebind"
            )));
        }
        write_sysfs(&dir.join("driver").join("unbind"), addr).await?;
    }

    // driver_override pins the device to vfio-pci for the subsequent bind.
    write_sysfs(&dir.join("driver_override"), "vfio-pci").await?;
    // Ignore an "already bound"/EBUSY here — the override + a fresh bind is
    // best-effort and the device may already be attached.
    let _ = write_sysfs(&PathBuf::from("/sys/bus/pci/drivers/vfio-pci/bind"), addr).await;
    Ok(())
}

/// The PCI addresses sharing `dir`'s IOMMU group (including itself). Falls back
/// to just the device when IOMMU is disabled.
async fn iommu_group_members(dir: &Path) -> ApiResult<Vec<String>> {
    let devices = dir.join("iommu_group").join("devices");
    let mut rd = match fs::read_dir(&devices).await {
        Ok(rd) => rd,
        Err(_) => {
            let self_addr = dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            return Ok(vec![self_addr]);
        }
    };
    let mut out = Vec::new();
    while let Some(entry) = rd
        .next_entry()
        .await
        .map_err(|e| AppError::internal(format!("read_dir {}: {e}", devices.display())))?
    {
        if let Some(name) = entry.file_name().to_str() {
            out.push(name.to_string());
        }
    }
    Ok(out)
}

/// Read a full [`GpuDevice`] from a PCI device directory.
async fn read_gpu(dir: &Path) -> Option<GpuDevice> {
    let pci_address = dir.file_name()?.to_str()?.to_string();
    let vendor_id = read_trimmed(&dir.join("vendor")).await.unwrap_or_default();
    let device_id = read_trimmed(&dir.join("device")).await.unwrap_or_default();
    let driver = current_driver(dir).await;
    let iommu_group = read_iommu_group(dir).await;

    let short_vendor = vendor_id.trim_start_matches("0x");
    let short_device = device_id.trim_start_matches("0x");

    Some(GpuDevice {
        pci_address,
        vendor: vendor_name(&vendor_id),
        model: read_trimmed(&dir.join("label"))
            .await
            .unwrap_or_else(|| format!("{short_vendor}:{short_device}")),
        pci_id: format!("{short_vendor}:{short_device}"),
        iommu_group,
        available: driver.as_deref().map(|d| d == "vfio-pci").unwrap_or(true),
        assigned_to: None,
    })
}

/// Basename of the device's bound driver, if any.
async fn current_driver(dir: &Path) -> Option<String> {
    fs::read_link(dir.join("driver"))
        .await
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
}

async fn read_iommu_group(dir: &Path) -> u32 {
    fs::read_link(dir.join("iommu_group"))
        .await
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(0)
}

fn vendor_name(vendor_id: &str) -> String {
    match vendor_id.trim().to_ascii_lowercase().as_str() {
        "0x10de" => "NVIDIA".to_string(),
        "0x1002" => "AMD".to_string(),
        "0x8086" => "Intel".to_string(),
        other => other.to_string(),
    }
}

async fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path)
        .await
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

async fn write_sysfs(path: &Path, value: &str) -> ApiResult<()> {
    fs::write(path, value)
        .await
        .map_err(|e| AppError::hypervisor(format!("write {}: {e}", path.display())))
}
