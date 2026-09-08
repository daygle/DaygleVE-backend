//! USB passthrough service: host USB device inventory from sysfs.
//!
//! Enumerates real USB devices under `/sys/bus/usb/devices` (each carries
//! `idVendor`/`idProduct`), skipping USB interfaces (named `X-Y:Z.W`, no
//! `idVendor`) and hubs. Devices are keyed by USB `vendor:product` - the same
//! stable identity a VM passes through - and de-duplicated so identical devices
//! appear once. Attachment itself is handled by the KVM service via a
//! `<hostdev type='usb'>` element; this service only inventories.

use std::collections::HashSet;

use daygleve_schema::usb::UsbDevice;
use tokio::fs;

use crate::error::{ApiResult, AppError};
use crate::services::is_hex4;

const USB_DEVICES: &str = "/sys/bus/usb/devices";

pub struct UsbService;

impl Default for UsbService {
    fn default() -> Self {
        Self::new()
    }
}

impl UsbService {
    pub fn new() -> Self {
        Self
    }

    /// Host USB devices eligible for passthrough, one row per unique
    /// `vendor:product`, sorted by description.
    pub async fn list(&self) -> ApiResult<Vec<UsbDevice>> {
        let mut out: Vec<UsbDevice> = Vec::new();
        let mut seen: HashSet<(String, String)> = HashSet::new();
        let mut rd = match fs::read_dir(USB_DEVICES).await {
            Ok(rd) => rd,
            // No USB sysfs (non-Linux/dev host): nothing to enumerate.
            Err(_) => return Ok(out),
        };
        while let Some(entry) = rd
            .next_entry()
            .await
            .map_err(|e| AppError::internal(format!("read_dir {USB_DEVICES}: {e}")))?
        {
            let dir = entry.path();
            // Only real devices carry idVendor/idProduct; interfaces do not.
            let (Some(vendor_id), Some(product_id)) = (
                read_trimmed(&dir.join("idVendor")).await,
                read_trimmed(&dir.join("idProduct")).await,
            ) else {
                continue;
            };
            if !is_hex4(&vendor_id) || !is_hex4(&product_id) {
                continue;
            }
            // Skip hubs (USB device class 0x09) - they aren't meaningfully
            // attachable and only add noise.
            if read_trimmed(&dir.join("bDeviceClass")).await.as_deref() == Some("09") {
                continue;
            }
            if !seen.insert((vendor_id.clone(), product_id.clone())) {
                continue;
            }
            let manufacturer = read_trimmed(&dir.join("manufacturer"))
                .await
                .unwrap_or_default();
            let product = read_trimmed(&dir.join("product")).await.unwrap_or_default();
            let description = match (manufacturer.trim(), product.trim()) {
                ("", "") => format!("{vendor_id}:{product_id}"),
                ("", p) => p.to_string(),
                (m, "") => m.to_string(),
                (m, p) => format!("{m} {p}"),
            };
            out.push(UsbDevice {
                vendor_id,
                product_id,
                description,
            });
        }
        out.sort_by(|a, b| a.description.cmp(&b.description));
        Ok(out)
    }
}

async fn read_trimmed(path: &std::path::Path) -> Option<String> {
    fs::read_to_string(path)
        .await
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
