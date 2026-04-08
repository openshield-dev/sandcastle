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
    ///
    /// Returns an error if `pci_address` does not match the `DDDD:BB:DD.F`
    /// format (e.g. `"0000:01:00.0"`), where each segment consists of
    /// hexadecimal digits only.
    pub fn new(pci_address: String) -> Result<Self, GpuError> {
        Self::validate_pci_address(&pci_address)?;
        Ok(Self {
            pci_address,
            iommu_group: None,
        })
    }

    /// Validate that `addr` matches the PCI address format `DDDD:BB:DD.F`.
    ///
    /// Rules:
    /// - Total length must be exactly 12 characters.
    /// - Characters at positions 4 and 7 must be `':'`.
    /// - Character at position 10 must be `'.'`.
    /// - All other characters must be ASCII hexadecimal digits.
    fn validate_pci_address(addr: &str) -> Result<(), GpuError> {
        // Expected layout: "DDDD:BB:DD.F"  (0-indexed positions)
        //  0123 4 56 7 89 10 11
        //  DDDD : BB : DD .  F
        if addr.len() != 12 {
            return Err(GpuError::ConfigError(format!(
                "PCI address must be exactly 12 characters (e.g. '0000:01:00.0'), got '{addr}'"
            )));
        }
        let bytes = addr.as_bytes();
        for (i, &b) in bytes.iter().enumerate() {
            match i {
                4 | 7 => {
                    if b != b':' {
                        return Err(GpuError::ConfigError(format!(
                            "PCI address must have ':' at position {i}, got '{addr}'"
                        )));
                    }
                }
                10 => {
                    if b != b'.' {
                        return Err(GpuError::ConfigError(format!(
                            "PCI address must have '.' at position {i}, got '{addr}'"
                        )));
                    }
                }
                _ => {
                    if !b.is_ascii_hexdigit() {
                        return Err(GpuError::ConfigError(format!(
                            "PCI address contains invalid character '{}' at position {i} in '{addr}'",
                            b as char
                        )));
                    }
                }
            }
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::VfioConfig;

    #[test]
    fn valid_pci_address_accepted() {
        assert!(VfioConfig::new("0000:01:00.0".into()).is_ok());
        assert!(VfioConfig::new("abcd:ef:12.3".into()).is_ok());
    }

    #[test]
    fn invalid_pci_address_rejected() {
        assert!(VfioConfig::new("../../etc".into()).is_err());
        assert!(VfioConfig::new("too-short".into()).is_err());
        assert!(VfioConfig::new("0000-01-00.0".into()).is_err()); // wrong separator
        assert!(VfioConfig::new("".into()).is_err());
        assert!(VfioConfig::new("0000:01:00:0".into()).is_err()); // colon instead of dot
    }
}
