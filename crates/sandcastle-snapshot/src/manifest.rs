//! Snapshot manifest — metadata stored alongside each snapshot archive.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Metadata describing a single sandbox snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// Unique snapshot identifier.
    pub id: Uuid,
    /// Human-readable label (e.g. "before-npm-install").
    pub label: String,
    /// Sandbox instance this snapshot belongs to.
    pub sandbox_id: String,
    /// Wall-clock time the snapshot was taken.
    pub created_at: DateTime<Utc>,
    /// Uncompressed size of the captured diff in bytes.
    pub diff_bytes: u64,
}

impl SnapshotManifest {
    /// Create a new manifest with the current timestamp.
    pub fn new(label: impl Into<String>, sandbox_id: impl Into<String>, diff_bytes: u64) -> Self {
        Self {
            id: Uuid::new_v4(),
            label: label.into(),
            sandbox_id: sandbox_id.into(),
            created_at: Utc::now(),
            diff_bytes,
        }
    }
}
