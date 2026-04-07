//! Error types for snapshot operations.

use thiserror::Error;

/// Errors produced by the snapshot layer.
#[derive(Error, Debug)]
pub enum SnapshotError {
    #[error("snapshot not found: {0}")]
    NotFound(String),

    #[error("failed to create snapshot: {0}")]
    CreateFailed(String),

    #[error("failed to restore snapshot: {0}")]
    RestoreFailed(String),

    #[error("snapshot manifest is corrupt: {0}")]
    CorruptManifest(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
