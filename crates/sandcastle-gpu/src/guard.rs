//! GPU guard — enforces GPU access policy for a sandbox.

use crate::error::GpuError;
use sandcastle_policy::SandboxProfile;

/// Enforces GPU policy for a single sandbox instance.
#[derive(Debug)]
pub struct GpuGuard {
    profile: SandboxProfile,
}

impl GpuGuard {
    /// Create a guard from the given sandbox profile.
    pub fn new(profile: SandboxProfile) -> Self {
        Self { profile }
    }

    /// Return `Ok(())` if GPU access is allowed by the policy.
    pub fn check_access(&self) -> Result<(), GpuError> {
        if self.profile.permissions.gpu.enabled {
            Ok(())
        } else {
            Err(GpuError::Denied)
        }
    }
}
