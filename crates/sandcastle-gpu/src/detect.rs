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
/// Attempts detection via `nvidia-smi` (NVIDIA), with fallback to an empty
/// list on systems without supported GPUs. Future versions will add AMD
/// ROCm SMI, Intel Level-Zero, and macOS Metal device enumeration.
pub fn detect_gpus() -> Result<Vec<GpuInfo>, GpuError> {
    let mut gpus = Vec::new();

    // Try NVIDIA detection via nvidia-smi.
    if let Ok(nvidia_gpus) = detect_nvidia_gpus() {
        gpus.extend(nvidia_gpus);
    }

    tracing::info!(count = gpus.len(), "GPU detection complete");
    Ok(gpus)
}

/// Detect NVIDIA GPUs by parsing `nvidia-smi --query-gpu` output.
fn detect_nvidia_gpus() -> Result<Vec<GpuInfo>, GpuError> {
    use std::process::Command;

    let output = Command::new("nvidia-smi")
        .args([
            "--query-gpu=index,name,memory.total,driver_version,compute_cap",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .map_err(|e| GpuError::QueryFailed(format!("nvidia-smi not found or failed: {e}")))?;

    if !output.status.success() {
        return Err(GpuError::QueryFailed(
            "nvidia-smi returned non-zero exit code".into(),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut gpus = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split(", ").collect();
        if parts.len() < 5 {
            continue;
        }

        let index = parts[0].trim().parse::<u32>().unwrap_or(0);
        let name = parts[1].trim().to_string();
        let memory_mb = parts[2].trim().parse::<u64>().unwrap_or(0);
        let driver_version = Some(parts[3].trim().to_string());
        let compute_cap = Some(parts[4].trim().to_string());

        gpus.push(GpuInfo {
            index,
            name,
            vendor: GpuVendor::Nvidia,
            memory_mb,
            driver_version,
            compute_capability: compute_cap,
            available: true,
        });
    }

    Ok(gpus)
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
