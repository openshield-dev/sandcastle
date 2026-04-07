//! Filesystem guard — checks paths against the active policy.

use crate::error::FsError;
use sandcastle_policy::SandboxProfile;
use std::path::Path;

/// Enforces filesystem policy for a single sandbox instance.
#[derive(Debug)]
pub struct FsGuard {
    profile: SandboxProfile,
}

impl FsGuard {
    /// Create a guard from the given sandbox profile.
    pub fn new(profile: SandboxProfile) -> Self {
        Self { profile }
    }

    /// Return `Ok(())` if `path` is allowed for reading, or an error.
    pub fn check_read(&self, path: &Path) -> Result<(), FsError> {
        // Stub: full glob matching will be implemented in a later milestone.
        let _ = path;
        Ok(())
    }

    /// Return `Ok(())` if `path` is allowed for writing, or an error.
    pub fn check_write(&self, path: &Path) -> Result<(), FsError> {
        // Stub: full glob matching will be implemented in a later milestone.
        let _ = path;
        Ok(())
    }
}
