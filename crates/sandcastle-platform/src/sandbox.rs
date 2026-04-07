//! Sandbox trait, configuration types, and factory function.

use crate::error::PlatformError;
use sandcastle_policy::SandboxProfile;
use std::path::PathBuf;
use std::process::ExitStatus;

/// Configuration passed to the sandbox factory
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// The sandbox profile (permissions, trust level, etc.)
    pub profile: SandboxProfile,
    /// Working directory for the sandboxed process
    pub working_dir: PathBuf,
    /// Command to execute inside the sandbox
    pub command: String,
    /// Arguments to pass to the command
    pub args: Vec<String>,
    /// Environment variables for the sandboxed process (name, value)
    pub env: Vec<(String, String)>,
    /// Whether to attach stdin/stdout/stderr of the caller to the sandbox
    pub interactive: bool,
    /// When true, policy violations are logged but not blocked
    pub audit_mode: bool,
}

impl SandboxConfig {
    /// Create a minimal config for the given command using the default profile
    pub fn simple(command: impl Into<String>) -> Self {
        Self {
            profile: SandboxProfile::default(),
            working_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            command: command.into(),
            args: Vec::new(),
            env: Vec::new(),
            interactive: false,
            audit_mode: false,
        }
    }
}

/// Lifecycle state of a sandbox instance
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxStatus {
    /// The sandbox has been created but the child process has not started yet
    Created,
    /// The child process is running inside the sandbox
    Running,
    /// The child process has exited (successfully or not)
    Stopped,
    /// The sandbox could not be set up or the process crashed abnormally
    Failed(String),
}

/// Platform-agnostic interface to an OS sandbox.
///
/// Each supported platform provides its own implementation:
/// - Linux: kernel namespaces + Landlock + seccomp-BPF + cgroups v2
/// - macOS: `sandbox-exec` profiles + Endpoint Security (stub)
/// - Windows: Job Objects + AppContainer + optional Hyper-V isolation
///
/// Call [`create_sandbox`] to obtain a boxed implementation for the current OS.
pub trait Sandbox: Send + Sync {
    /// Create and configure the sandbox environment (does not start the process)
    fn create(config: SandboxConfig) -> Result<Self, PlatformError>
    where
        Self: Sized;

    /// Launch the sandboxed process
    fn start(&mut self) -> Result<(), PlatformError>;

    /// Block until the sandboxed process exits and return its exit status
    fn wait(&mut self) -> Result<ExitStatus, PlatformError>;

    /// Return the current lifecycle state of this sandbox
    fn status(&self) -> SandboxStatus;

    /// Forcibly terminate the sandboxed process
    fn terminate(&mut self) -> Result<(), PlatformError>;

    /// Return the unique ID assigned to this sandbox instance
    fn id(&self) -> &str;
}

/// Construct the appropriate sandbox implementation for the current OS.
///
/// Returns a `Box<dyn Sandbox>` so callers are decoupled from platform details.
pub fn create_sandbox(config: SandboxConfig) -> Result<Box<dyn Sandbox>, PlatformError> {
    #[cfg(target_os = "linux")]
    {
        use crate::linux::LinuxSandbox;
        return Ok(Box::new(LinuxSandbox::create(config)?));
    }

    #[cfg(target_os = "macos")]
    {
        use crate::macos::MacOSSandbox;
        return Ok(Box::new(MacOSSandbox::create(config)?));
    }

    #[cfg(target_os = "windows")]
    {
        use crate::windows::WindowsSandbox;
        return Ok(Box::new(WindowsSandbox::create(config)?));
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(PlatformError::Unsupported(
        std::env::consts::OS.to_string(),
    ))
}
