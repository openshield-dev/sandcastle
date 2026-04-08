#![forbid(unsafe_code)]
//! Filesystem isolation, path allowlisting, and virtual overlay management for SandCastle.
//!
//! This crate enforces the filesystem portion of a [`sandcastle_policy::SandboxProfile`]:
//! it validates every path access against the policy's allow/deny lists and provides
//! helpers for setting up temporary working trees for isolated agents.

pub mod bind;
pub mod cow;
pub mod error;
pub mod guard;
pub mod isolation;
pub mod overlay;
pub mod tmpfs;

pub use error::FsError;
pub use guard::FsGuard;
