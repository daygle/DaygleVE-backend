//! General PCI passthrough service: non-GPU host PCI inventory from sysfs.
//!
//! Enumerates PCI functions under `/sys/bus/pci/devices`, excluding display
//! controllers (base class 0x03 - those belong to the GPU flow) and PCI bridges
//! (base class 0x06 - not meaningfully attachable). The vfio bind step reuses
//! the GPU service's `bind`, since binding a function to `vfio-pci` is the same
//! operation regardless of device class.

use std::path::Path;

use daygleve_schema::pci::PciDevice;
use tokio::fs;

use crate::error::{ApiResult, AppError};
use crate::services::ensure_safe_pci_address;
use crate::services::gpu::{current_driver, read_iommu_group, read_trimmed, vendor_name};

const PCI_DEVICES: &str = "/sys/bus/pci/devices";

pub struct PciService;

impl Default for PciService {
    fn default() -> Self {
        Self::new()
    }
}

impl PciService {
    pub fn new() -> Self {
        Self
    }

    /// Host PCI functions eligible for passthrough (non-display, non-bridge),
    /// sorted by PCI address.
    pub async fn list(&self) -> ApiResult<Vec<PciDevice>> {
        let mut out: Vec<PciDevice> = Vec::new();
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
            // 0x03xxxx = display (GPU flow); 0x06xxxx = PCI bridge (not attachable).
            if class.starts_with("0x03") || class.starts_with("0x06") {
                continue;
            }
            if let Some(dev) = read_pci(&dir, &class).await {
                out.push(dev);
            }
        }
        out.sort_by(|a, b| a.pci_address.cmp(&b.pci_address));
        Ok(out)
    }
}

/// Read a [`PciDevice`] from a PCI device directory, given its `class` string.
async fn read_pci(dir: &Path, class: &str) -> Option<PciDevice> {
    let pci_address = dir.file_name()?.to_str()?.to_string();
    ensure_safe_pci_address(&pci_address).ok()?;
    let vendor_id = read_trimmed(&dir.join("vendor")).await.unwrap_or_default();
    let device_id = read_trimmed(&dir.join("device")).await.unwrap_or_default();
    let short_vendor = vendor_id.trim_start_matches("0x");
    let short_device = device_id.trim_start_matches("0x");
    let driver = current_driver(dir).await;
    Some(PciDevice {
        pci_address,
        pci_id: format!("{short_vendor}:{short_device}"),
        vendor: vendor_name(&vendor_id),
        class: class_category(class),
        iommu_group: read_iommu_group(dir).await,
        available: driver.as_deref() == Some("vfio-pci"),
    })
}

/// Map a PCI `class` string (e.g. `0x020000`) to a coarse, human category from
/// its base-class byte. Unknown classes fall back to `Other`.
fn class_category(class: &str) -> String {
    let base = class.trim_start_matches("0x");
    let base = base.get(..2).unwrap_or("");
    match base {
        "00" => "Unclassified",
        "01" => "Storage",
        "02" => "Network",
        "04" => "Multimedia",
        "05" => "Memory",
        "07" => "Communication",
        "08" => "System peripheral",
        "09" => "Input",
        "0a" => "Docking",
        "0b" => "Processor",
        "0c" => "Serial bus",
        "0d" => "Wireless",
        "0e" => "Intelligent controller",
        "0f" => "Satellite",
        "10" => "Encryption",
        "11" => "Signal processing",
        "12" => "Accelerator",
        _ => "Other",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_categories_map_common_base_classes() {
        assert_eq!(class_category("0x020000"), "Network");
        assert_eq!(class_category("0x010802"), "Storage");
        assert_eq!(class_category("0x0c0330"), "Serial bus");
        assert_eq!(class_category("0xffffff"), "Other");
        assert_eq!(class_category(""), "Other");
    }
}
