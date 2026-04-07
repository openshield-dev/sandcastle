//! Error types for platform isolation operations.

use thiserror::Error;

/// Errors produced by the platform isolation layer.
#[derive(Error, Debug)]
pub enum PlatformError {
    /// The current OS is not supported by this build of SandCastle
    #[error("unsupported platform: {0}")]
    Unsupported(String),

    /// Sandbox creation failed before the child process was launched
    #[error("failed to create sandbox: {0}")]
    CreateFailed(String),

    /// An operation was refused due to insufficient OS privileges
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// An operation was attempted on a sandbox that is not running
    #[error("sandbox not running")]
    NotRunning,

    /// The sandboxed process could not be executed
    #[error("process execution failed: {0}")]
    ExecFailed(String),

    /// Failed to enter or configure a kernel namespace
    #[error("failed to enter namespace: {0}")]
    NamespaceFailed(String),

    /// A seccomp BPF filter could not be applied
    #[error("failed to apply seccomp filter: {0}")]
    SeccompFailed(String),

    /// A Landlock ruleset could not be configured
    #[error("landlock configuration failed: {0}")]
    LandlockFailed(String),

    /// A cgroup resource limit could not be applied
    #[error("cgroup resource limit error: {0}")]
    CgroupFailed(String),

    /// A Windows Job Object operation failed
    #[error("job object error: {0}")]
    JobObjectFailed(String),

    /// An AppContainer security attribute could not be configured
    #[error("AppContainer setup failed: {0}")]
    AppContainerFailed(String),

    /// Transparent wrapper around I/O errors
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
