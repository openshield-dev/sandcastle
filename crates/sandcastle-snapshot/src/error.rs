//! Error types for snapshot operations.

use thiserror::Error;

/// Errors produced by the snapshot layer.
#[derive(Error, Debug)]
pub enum SnapshotError {
    #[error("Snapshot not found: {0}")]
    NotFound(String),

    #[error("Snapshot already exists: {0}")]
    AlreadyExists(String),

    #[error("Invalid snapshot name: {0}")]
    InvalidName(String),

    #[error("Branch not found: {0}")]
    BranchNotFound(String),

    #[error("Restore failed: {0}")]
    RestoreFailed(String),

    #[error("Snapshot corrupted: {0}")]
    Corrupted(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
