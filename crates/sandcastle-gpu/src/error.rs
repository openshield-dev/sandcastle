use thiserror::Error;

/// Errors produced by the GPU isolation and passthrough layer.
#[derive(Error, Debug)]
pub enum GpuError {
    #[error("No GPU detected")]
    NoGpuDetected,
    #[error("GPU not supported for passthrough: {0}")]
    NotSupported(String),
    #[error("GPU passthrough method not available: {0}")]
    MethodNotAvailable(String),
    #[error("GPU already in use by another sandbox")]
    AlreadyInUse,
    #[error("Driver error: {0}")]
    DriverError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    /// Policy denied GPU access (used by GpuGuard).
    #[error("GPU access denied by policy")]
    Denied,
    /// A specific device was not found.
    #[error("GPU device not found: {0}")]
    DeviceNotFound(String),
    /// Low-level query failed.
    #[error("failed to query GPU devices: {0}")]
    QueryFailed(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
