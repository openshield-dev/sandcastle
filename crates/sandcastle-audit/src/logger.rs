//! Audit logger — collects and emits [`AuditEvent`]s.

use crate::event::AuditEvent;
use tracing::info;

/// Receives audit events and forwards them to the tracing subscriber.
///
/// Future versions will support writing to structured log files or a
/// remote aggregation endpoint.
#[derive(Debug, Default)]
pub struct AuditLogger {
    sandbox_id: String,
}

impl AuditLogger {
    /// Create a logger scoped to the given sandbox instance.
    pub fn new(sandbox_id: impl Into<String>) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
        }
    }

    /// Record an audit event.
    pub fn record(&self, event: &AuditEvent) {
        info!(
            event_id = %event.id,
            sandbox_id = %event.sandbox_id,
            kind = ?event.kind,
            allowed = event.allowed,
            detail = %event.detail,
            "audit"
        );
    }
}
