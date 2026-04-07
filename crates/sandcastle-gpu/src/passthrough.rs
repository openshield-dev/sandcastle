//! GPU passthrough orchestrator — routes setup/teardown to the correct backend.

use crate::{
    detect::{GpuInfo, PassthroughMethod},
    error::GpuError,
};

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
        if let Some(frac) = config.compute_limit {
            if !(0.0..=1.0).contains(&frac) {
                return Err(GpuError::ConfigError(format!(
                    "compute_limit must be between 0.0 and 1.0, got {frac}"
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
    pub fn setup(&mut self) -> Result<(), GpuError> {
        match self.config.method {
            PassthroughMethod::NvProxy => self.setup_nvproxy(),
            PassthroughMethod::Vfio => self.setup_vfio(),
            PassthroughMethod::GpuPv => self.setup_gpu_pv(),
            PassthroughMethod::Direct => self.setup_direct(),
        }
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
        self.active = false;
        Ok(())
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
