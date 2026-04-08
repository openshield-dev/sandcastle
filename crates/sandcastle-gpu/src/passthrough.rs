//! GPU passthrough orchestrator — routes setup/teardown to the correct backend.

use std::collections::HashSet;
use std::sync::{LazyLock, Mutex};

use crate::{
    detect::{GpuInfo, PassthroughMethod},
    error::GpuError,
};

/// Maximum number of GPU devices a single sandbox may request.
const MAX_GPU_DEVICES: usize = 16;

/// Maximum per-device memory limit in MB (~1 TB).
const MAX_MEMORY_LIMIT_MB: u64 = 1_000_000;

/// Tracks which device indices are currently allocated across all sandboxes.
static ALLOCATED_DEVICES: LazyLock<Mutex<HashSet<u32>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

/// Configuration for GPU passthrough in a sandbox.
#[derive(Debug, Clone)]
pub struct GpuPassthroughConfig {
    /// Which passthrough technique to use.
    pub method: PassthroughMethod,
    /// Indices of the GPU devices to expose.
    pub device_indices: Vec<u32>,
    /// Optional memory cap per device (MB).
    pub memory_limit: Option<u64>,
    /// Optional compute fraction cap per device (0.0 – 1.0).
    pub compute_limit: Option<f32>,
}

/// Manages GPU passthrough for a single sandbox instance.
#[derive(Debug)]
pub struct GpuPassthrough {
    pub config: GpuPassthroughConfig,
    pub gpus: Vec<GpuInfo>,
    pub active: bool,
}

impl GpuPassthrough {
    /// Create a new passthrough manager. Validates configuration but does not
    /// activate passthrough until [`setup`] is called.
    pub fn new(config: GpuPassthroughConfig) -> Result<Self, GpuError> {
        // Validate device count.
        if config.device_indices.len() > MAX_GPU_DEVICES {
            return Err(GpuError::ConfigError(format!(
                "too many GPU devices requested ({}, max {MAX_GPU_DEVICES})",
                config.device_indices.len()
            )));
        }

        // Validate compute_limit (NaN and range).
        if let Some(frac) = config.compute_limit {
            if frac.is_nan() || !(0.0..=1.0).contains(&frac) {
                return Err(GpuError::ConfigError(format!(
                    "compute_limit must be between 0.0 and 1.0, got {frac}"
                )));
            }
        }

        // Validate memory_limit.
        if let Some(mem) = config.memory_limit {
            if mem == 0 || mem > MAX_MEMORY_LIMIT_MB {
                return Err(GpuError::ConfigError(format!(
                    "memory_limit must be between 1 and {MAX_MEMORY_LIMIT_MB} MB, got {mem}"
                )));
            }
        }

        Ok(Self {
            config,
            gpus: vec![],
            active: false,
        })
    }

    /// Set up GPU passthrough using the configured method.
    ///
    /// Returns [`GpuError::AlreadyInUse`] if any of the requested device
    /// indices are currently allocated to another sandbox.
    pub fn setup(&mut self) -> Result<(), GpuError> {
        // Acquire the global allocation lock and check for conflicts.
        let mut allocated = ALLOCATED_DEVICES
            .lock()
            .expect("ALLOCATED_DEVICES mutex poisoned");

        for &idx in &self.config.device_indices {
            if allocated.contains(&idx) {
                return Err(GpuError::AlreadyInUse);
            }
        }

        // Reserve all requested devices before performing backend setup.
        for &idx in &self.config.device_indices {
            allocated.insert(idx);
        }

        // Release the lock before the (potentially slow) backend call.
        drop(allocated);

        let result = match self.config.method {
            PassthroughMethod::NvProxy => self.setup_nvproxy(),
            PassthroughMethod::Vfio => self.setup_vfio(),
            PassthroughMethod::GpuPv => self.setup_gpu_pv(),
            PassthroughMethod::Direct => self.setup_direct(),
        };

        // If backend setup failed, release the reserved devices.
        if result.is_err() {
            Self::release_devices(&self.config.device_indices);
        }

        result
    }

    /// Tear down GPU passthrough and release any resources.
    pub fn teardown(&mut self) -> Result<(), GpuError> {
        if !self.active {
            tracing::warn!("teardown called but passthrough is not active — no-op");
            return Ok(());
        }
        tracing::info!(
            method = ?self.config.method,
            devices = ?self.config.device_indices,
            "Tearing down GPU passthrough (stub)"
        );
        Self::release_devices(&self.config.device_indices);
        self.active = false;
        Ok(())
    }

    /// Remove `indices` from the global allocation set.
    fn release_devices(indices: &[u32]) {
        let mut allocated = ALLOCATED_DEVICES
            .lock()
            .expect("ALLOCATED_DEVICES mutex poisoned");
        for idx in indices {
            allocated.remove(idx);
        }
    }

    // ── private backend stubs ────────────────────────────────────────────────

    fn setup_nvproxy(&mut self) -> Result<(), GpuError> {
        tracing::info!(
            devices = ?self.config.device_indices,
            memory_limit_mb = ?self.config.memory_limit,
            "Setting up gVisor nvproxy GPU passthrough (stub)"
        );
        self.active = true;
        Ok(())
    }

    fn setup_vfio(&mut self) -> Result<(), GpuError> {
        tracing::info!(
            devices = ?self.config.device_indices,
            "Setting up VFIO GPU passthrough (stub)"
        );
        self.active = true;
        Ok(())
    }

    fn setup_gpu_pv(&mut self) -> Result<(), GpuError> {
        tracing::info!(
            devices = ?self.config.device_indices,
            memory_limit_mb = ?self.config.memory_limit,
            "Setting up Hyper-V GPU-PV passthrough (stub)"
        );
        self.active = true;
        Ok(())
    }

    fn setup_direct(&mut self) -> Result<(), GpuError> {
        tracing::info!(
            devices = ?self.config.device_indices,
            "Setting up direct GPU access (process-level sandbox) (stub)"
        );
        self.active = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(devices: Vec<u32>) -> GpuPassthroughConfig {
        GpuPassthroughConfig {
            method: PassthroughMethod::Direct,
            device_indices: devices,
            memory_limit: None,
            compute_limit: None,
        }
    }

    #[test]
    fn max_devices_enforced() {
        let devices: Vec<u32> = (0..17).collect();
        let result = GpuPassthrough::new(test_config(devices));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too many"));
    }

    #[test]
    fn nan_compute_limit_rejected() {
        let config = GpuPassthroughConfig {
            method: PassthroughMethod::Direct,
            device_indices: vec![0],
            memory_limit: None,
            compute_limit: Some(f32::NAN),
        };
        assert!(GpuPassthrough::new(config).is_err());
    }

    #[test]
    fn memory_limit_zero_rejected() {
        let config = GpuPassthroughConfig {
            method: PassthroughMethod::Direct,
            device_indices: vec![0],
            memory_limit: Some(0),
            compute_limit: None,
        };
        assert!(GpuPassthrough::new(config).is_err());
    }

    #[test]
    fn memory_limit_too_large_rejected() {
        let config = GpuPassthroughConfig {
            method: PassthroughMethod::Direct,
            device_indices: vec![0],
            memory_limit: Some(MAX_MEMORY_LIMIT_MB + 1),
            compute_limit: None,
        };
        assert!(GpuPassthrough::new(config).is_err());
    }

    #[test]
    fn valid_config_accepted() {
        let config = GpuPassthroughConfig {
            method: PassthroughMethod::Direct,
            device_indices: vec![0, 1],
            memory_limit: Some(8192),
            compute_limit: Some(0.5),
        };
        assert!(GpuPassthrough::new(config).is_ok());
    }

    #[test]
    fn allocation_tracking_prevents_double_use() {
        let mut pt1 = GpuPassthrough::new(test_config(vec![0])).unwrap();
        pt1.setup().unwrap();

        let mut pt2 = GpuPassthrough::new(test_config(vec![0])).unwrap();
        let result = pt2.setup();
        assert!(result.is_err());

        // After teardown, device should be available again.
        pt1.teardown().unwrap();
        assert!(pt2.setup().is_ok());
        pt2.teardown().unwrap();
    }
}

impl Drop for GpuPassthrough {
    fn drop(&mut self) {
        if self.active {
            tracing::warn!(
                method = ?self.config.method,
                devices = ?self.config.device_indices,
                "GpuPassthrough dropped while still active — running teardown"
            );
            if let Err(e) = self.teardown() {
                tracing::error!(error = %e, "teardown failed during drop");
            }
        }
    }
}
