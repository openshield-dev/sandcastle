//! VFIO GPU passthrough configuration.
//!
//! VFIO (Virtual Function I/O) provides hardware-level isolation by binding a
//! physical GPU to the `vfio-pci` kernel driver and exposing it exclusively to
//! one sandbox VM. This gives the strongest isolation guarantee at the cost of
//! dedicating the entire device to a single tenant.

use crate::error::GpuError;

/// VFIO GPU passthrough configuration.
#[derive(Debug, Clone)]
pub struct VfioConfig {
    /// PCI address of the GPU (e.g. `"0000:01:00.0"`).
    pub pci_address: String,
    /// IOMMU group number, if known. Resolved lazily when `None`.
    pub iommu_group: Option<u32>,
}

impl VfioConfig {
    /// Create a new VFIO config for the GPU at `pci_address`.
    pub fn new(pci_address: String) -> Self {
        Self {
            pci_address,
            iommu_group: None,
        }
    }

    /// Return `true` if the `vfio-pci` kernel module is loaded on this system.
    pub fn is_available() -> bool {
        #[cfg(target_os = "linux")]
        {
            // Would check: /sys/bus/pci/drivers/vfio-pci exists.
            tracing::info!("Checking VFIO availability (stub)");
            false
        }
        #[cfg(not(target_os = "linux"))]
        {
            tracing::warn!("VFIO is only supported on Linux");
            false
        }
    }

    /// Return `true` if an IOMMU (Intel VT-d or AMD-Vi) is active.
    pub fn check_iommu() -> Result<bool, GpuError> {
        #[cfg(target_os = "linux")]
        {
            // Would read /sys/kernel/iommu_groups/ or dmesg for IOMMU init.
            tracing::info!("Checking IOMMU status (stub)");
            Ok(false)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(GpuError::MethodNotAvailable(
                "IOMMU check is only supported on Linux".into(),
            ))
        }
    }

    /// Bind the device at `self.pci_address` to the `vfio-pci` driver.
    ///
    /// On a real system this would:
    /// 1. Write the PCI device ID to `/sys/bus/pci/drivers/<original>/unbind`
    /// 2. Write the PCI device ID to `/sys/bus/pci/drivers/vfio-pci/bind`
    pub fn bind_to_vfio(&self) -> Result<(), GpuError> {
        #[cfg(target_os = "linux")]
        {
            tracing::info!(
                pci_address = %self.pci_address,
                iommu_group = ?self.iommu_group,
                "Binding GPU to vfio-pci driver (stub)"
            );
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(GpuError::MethodNotAvailable(
                "VFIO is only supported on Linux".into(),
            ))
        }
    }

    /// Unbind from `vfio-pci` and restore the original driver.
    ///
    /// On a real system this would write back to the original driver's `bind`
    /// sysfs path so the GPU becomes available to the host again.
    pub fn unbind_from_vfio(&self) -> Result<(), GpuError> {
        #[cfg(target_os = "linux")]
        {
            tracing::info!(
                pci_address = %self.pci_address,
                "Unbinding GPU from vfio-pci, restoring original driver (stub)"
            );
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(GpuError::MethodNotAvailable(
                "VFIO is only supported on Linux".into(),
            ))
        }
    }
}
