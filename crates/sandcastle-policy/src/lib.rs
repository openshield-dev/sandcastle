//! Policy definition, parsing, and enforcement for SandCastle sandboxes.
//!
//! This crate provides the core types for describing what a sandboxed agent
//! is allowed to do: filesystem paths, network domains, process execution,
//! resource limits, and GPU access. Policies are expressed as [`SandboxProfile`]
//! values which are consumed by the platform, fs, network, and gpu crates.

pub mod error;
pub mod filter;
pub mod permission;
pub mod profile;
pub mod resolver;

pub use error::PolicyError;
pub use filter::{FilterAction, FilterGenerator, FilterRule, FilterTarget, GeneratedFilter};
pub use permission::{
    FsPermissions, GpuPermissions, NetworkPermissions, Permissions, ProcessPermissions,
    ResourceLimits, TrustLevel,
};
pub use profile::{BuiltinProfile, ProfileOverrides, SandboxProfile};
