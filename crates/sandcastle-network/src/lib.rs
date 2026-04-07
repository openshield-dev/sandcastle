//! Network isolation, egress filtering, and DNS control for SandCastle sandboxes.
//!
//! Stub implementation — full network isolation will be added in a subsequent milestone.

/// Network isolation configuration (stub)
#[derive(Debug, Clone, Default)]
pub struct NetworkIsolation {
    pub enabled: bool,
}
