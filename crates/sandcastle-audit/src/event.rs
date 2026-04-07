//! Core audit event types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The category of action being recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A filesystem operation (read, write, delete, …).
    Filesystem,
    /// An outbound network connection attempt.
    Network,
    /// A child process was spawned or blocked.
    Process,
    /// A sandbox snapshot was created or restored.
    Snapshot,
    /// A GPU resource was accessed or denied.
    Gpu,
    /// A sandbox was started or stopped.
    Lifecycle,
}

/// A single immutable audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier.
    pub id: Uuid,
    /// Wall-clock timestamp (UTC).
    pub timestamp: DateTime<Utc>,
    /// Sandbox instance that produced this event.
    pub sandbox_id: String,
    /// Category of the event.
    pub kind: EventKind,
    /// Whether the underlying action was permitted (`true`) or denied (`false`).
    pub allowed: bool,
    /// Human-readable description of the action.
    pub detail: String,
}

impl AuditEvent {
    /// Construct a new event with the current timestamp.
    pub fn new(
        sandbox_id: impl Into<String>,
        kind: EventKind,
        allowed: bool,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            sandbox_id: sandbox_id.into(),
            kind,
            allowed,
            detail: detail.into(),
        }
    }
}
