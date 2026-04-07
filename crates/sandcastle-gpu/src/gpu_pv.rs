//! Hyper-V GPU-PV (paravirtualized GPU) configuration for Windows.
//!
//! GPU-PV allows a Hyper-V virtual machine to share the host GPU through the
//! paravirtualization layer. AI workloads can access the GPU via DirectML
//! (native Windows) or via CUDA when running inside a WSL 2 distribution.

use crate::error::GpuError;

/// Hyper-V GPU-PV configuration.
#[derive(Debug, Clone)]
pub struct GpuPvConfig {
    /// `true` → expose the GPU through WSL 2 for CUDA access.
    /// `false` → use DirectML / Direct3D 12 natively in the Windows container.
    pub use_wsl2: bool,
    /// Amount of GPU memory to allocate to the VM (MB). `None` uses the
    /// Hyper-V default allocation policy.
    pub memory_mb: Option<u64>,
}

impl GpuPvConfig {
    /// Create a new GPU-PV configuration.
    pub fn new(use_wsl2: bool) -> Self {
        Self {
            use_wsl2,
            memory_mb: None,
        }
    }

    /// Return `true` if GPU-PV is available on this system.
    ///
    /// Requires Windows 11 (or Windows Server 2022+) with Hyper-V enabled and
    /// a compatible WDDM 2.9+ graphics driver.
    pub fn is_available() -> bool {
        #[cfg(target_os = "windows")]
        {
            // Would query: Win32_VideoController via WMI, or check
            // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization.
            tracing::info!("Checking Hyper-V GPU-PV availability (stub)");
            false
        }
        #[cfg(not(target_os = "windows"))]
        {
            tracing::warn!("GPU-PV is only supported on Windows");
            false
        }
    }

    /// Set up GPU-PV for a Hyper-V container.
    ///
    /// On a real system this would configure the VM's GPU partitioning via the
    /// Hyper-V WMI API or `Set-VMGpuPartitionAdapter` PowerShell cmdlet.
    pub fn setup(&self) -> Result<(), GpuError> {
        #[cfg(target_os = "windows")]
        {
            tracing::info!(
                use_wsl2 = self.use_wsl2,
                memory_mb = ?self.memory_mb,
                "Setting up Hyper-V GPU-PV (stub)"
            );
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(GpuError::MethodNotAvailable(
                "GPU-PV is only supported on Windows".into(),
            ))
        }
    }

    /// Tear down GPU-PV and release the partition allocation.
    pub fn teardown(&self) -> Result<(), GpuError> {
        #[cfg(target_os = "windows")]
        {
            tracing::info!("Tearing down Hyper-V GPU-PV (stub)");
            Ok(())
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(GpuError::MethodNotAvailable(
                "GPU-PV is only supported on Windows".into(),
            ))
        }
    }
}
