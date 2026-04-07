//! Error types for GPU isolation operations.

use thiserror::Error;

/// Errors produced by the GPU isolation layer.
#[derive(Error, Debug)]
pub enum GpuError {
    #[error("GPU access denied by policy")]
    Denied,

    #[error("GPU device not found: {0}")]
    DeviceNotFound(String),

    #[error("failed to query GPU devices: {0}")]
    QueryFailed(String),
}
