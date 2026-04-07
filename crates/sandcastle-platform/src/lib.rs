//! Platform-specific OS isolation primitives for SandCastle.
//!
//! On Linux this crate wraps kernel namespaces, Landlock LSM, seccomp-BPF
//! filters, and cgroup-v2 resource controls.  On macOS it uses `sandbox-exec`
//! profiles and the Endpoint Security framework.  On Windows it wraps Job
//! Objects, AppContainer, and optional Hyper-V process isolation.
//!
//! The public API is platform-agnostic; all platform details are hidden behind
//! `#[cfg(target_os = "...")]` modules.  Use [`sandbox::create_sandbox`] to
//! obtain a boxed [`sandbox::Sandbox`] implementation for the current OS.

pub mod error;
pub mod sandbox;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

pub use error::PlatformError;
pub use sandbox::{create_sandbox, Sandbox, SandboxConfig, SandboxStatus};
