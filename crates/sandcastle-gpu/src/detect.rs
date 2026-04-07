//! GPU detection — enumerate available GPUs and recommend a passthrough method.

use serde::{Deserialize, Serialize};

use crate::error::GpuError;

/// Information about a single GPU device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub index: u32,
    pub name: String,
    pub vendor: GpuVendor,
    pub memory_mb: u64,
    pub driver_version: Option<String>,
    pub compute_capability: Option<String>,
    pub available: bool,
}

/// GPU vendor classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GpuVendor {
    Nvidia,
    Amd,
    Intel,
    Apple,
    Unknown(String),
}

/// The isolation technique used to expose a GPU to a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PassthroughMethod {
    /// gVisor nvproxy — syscall filtering for NVIDIA GPUs (Linux).
    NvProxy,
    /// VFIO passthrough — hardware isolation, one GPU per sandbox (Linux).
    Vfio,
    /// Hyper-V GPU-PV — paravirtualized GPU (Windows).
    GpuPv,
    /// Direct access — process-level sandboxing only (macOS Metal/CoreML).
    Direct,
}

/// Detect all available GPUs on the host system.
///
/// This is a stub implementation. On a real host the function would query
/// `nvidia-smi`, `/proc/driver/nvidia/gpus`, the ROCm SMI, Intel Level-Zero,
/// or the macOS Metal device list depending on the platform.
pub fn detect_gpus() -> Result<Vec<GpuInfo>, GpuError> {
    tracing::info!("GPU detection requested — stub implementation, returning empty list");
    Ok(vec![])
}

/// Return the recommended passthrough method for the current host platform.
pub fn recommended_method() -> PassthroughMethod {
    #[cfg(target_os = "linux")]
    {
        PassthroughMethod::NvProxy
    }
    #[cfg(target_os = "windows")]
    {
        PassthroughMethod::GpuPv
    }
    #[cfg(target_os = "macos")]
    {
        PassthroughMethod::Direct
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        PassthroughMethod::Direct
    }
}

/// Report whether a specific passthrough method is usable on the current host.
pub fn is_method_available(method: &PassthroughMethod) -> bool {
    match method {
        PassthroughMethod::NvProxy => {
            #[cfg(target_os = "linux")]
            {
                // Would check: /proc/driver/nvidia exists and gVisor runsc is installed.
                tracing::info!("Checking nvproxy availability (stub)");
                false
            }
            #[cfg(not(target_os = "linux"))]
            false
        }
        PassthroughMethod::Vfio => {
            #[cfg(target_os = "linux")]
            {
                // Would check: /sys/bus/pci/drivers/vfio-pci and IOMMU enablement.
                tracing::info!("Checking VFIO availability (stub)");
                false
            }
            #[cfg(not(target_os = "linux"))]
            false
        }
        PassthroughMethod::GpuPv => {
            #[cfg(target_os = "windows")]
            {
                // Would check: Hyper-V capabilities via PowerShell or WMI.
                tracing::info!("Checking GPU-PV availability (stub)");
                false
            }
            #[cfg(not(target_os = "windows"))]
            false
        }
        PassthroughMethod::Direct => {
            // Direct access is always nominally available as a fallback.
            true
        }
    }
}
