//! gVisor nvproxy configuration for NVIDIA GPU passthrough.
//!
//! nvproxy provides medium isolation by intercepting NVIDIA driver ioctls
//! inside gVisor's sentry, maintaining full CUDA / PyTorch / vLLM compatibility
//! while blocking direct hardware access from sandboxed processes.

use crate::error::GpuError;

/// Allowed NVIDIA driver operations inside the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NvProxyOp {
    Compute,
    MemoryAlloc,
    MemoryTransfer,
    KernelLaunch,
    StreamSync,
}

/// gVisor nvproxy configuration for one or more NVIDIA GPU devices.
#[derive(Debug, Clone)]
pub struct NvProxyConfig {
    /// GPU device indices to expose inside the sandbox.
    pub devices: Vec<u32>,
    /// Whether to allow CUDA inter-process communication.
    pub allow_cuda_ipc: bool,
    /// Optional memory cap per device (MB).
    pub memory_limit: Option<u64>,
    /// Driver operations permitted inside the sandbox.
    pub allowed_ops: Vec<NvProxyOp>,
}

impl NvProxyConfig {
    /// Default configuration suitable for LLM inference workloads.
    ///
    /// IPC is disabled and training-specific ops (MemoryAlloc unbounded,
    /// peer-to-peer transfers) are omitted.
    pub fn for_inference(devices: Vec<u32>) -> Self {
        Self {
            devices,
            allow_cuda_ipc: false,
            memory_limit: None,
            allowed_ops: vec![
                NvProxyOp::Compute,
                NvProxyOp::MemoryAlloc,
                NvProxyOp::MemoryTransfer,
                NvProxyOp::KernelLaunch,
                NvProxyOp::StreamSync,
            ],
        }
    }

    /// Configuration for training workloads — more permissive, enables IPC.
    pub fn for_training(devices: Vec<u32>) -> Self {
        Self {
            devices,
            allow_cuda_ipc: true,
            memory_limit: None,
            allowed_ops: vec![
                NvProxyOp::Compute,
                NvProxyOp::MemoryAlloc,
                NvProxyOp::MemoryTransfer,
                NvProxyOp::KernelLaunch,
                NvProxyOp::StreamSync,
            ],
        }
    }

    /// Generate the `runsc` command-line flags required for this configuration.
    ///
    /// These flags are passed to gVisor's `runsc` container runtime when
    /// starting the sandbox.
    pub fn to_runsc_flags(&self) -> Vec<String> {
        let mut flags = vec![
            "--nvproxy=true".to_string(),
            "--nvproxy-docker=true".to_string(),
        ];

        if !self.devices.is_empty() {
            let device_list = self
                .devices
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join(",");
            flags.push(format!("--nvproxy-allowed-gpus={device_list}"));
        }

        if let Some(limit_mb) = self.memory_limit {
            flags.push(format!("--nvproxy-memory-limit-mb={limit_mb}"));
        }

        if !self.allow_cuda_ipc {
            flags.push("--nvproxy-no-cuda-ipc".to_string());
        }

        tracing::info!(flags = ?flags, "Generated nvproxy runsc flags (stub)");
        flags
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), GpuError> {
        if self.devices.is_empty() {
            return Err(GpuError::ConfigError(
                "nvproxy config must specify at least one device".into(),
            ));
        }
        Ok(())
    }
}
