//! Network egress filter — validates outbound connections against policy.

use crate::error::NetworkError;
use sandcastle_policy::SandboxProfile;

/// Enforces network policy for a single sandbox instance.
#[derive(Debug)]
pub struct NetworkFilter {
    profile: SandboxProfile,
}

impl NetworkFilter {
    /// Create a filter from the given sandbox profile.
    pub fn new(profile: SandboxProfile) -> Self {
        Self { profile }
    }

    /// Return `Ok(())` if a connection to `domain` is allowed by the policy.
    pub fn check_domain(&self, domain: &str) -> Result<(), NetworkError> {
        // Stub: full wildcard domain matching will be added in a later milestone.
        let _ = domain;
        Ok(())
    }
}
