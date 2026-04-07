//! Error types for the audit crate.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuditError {
    #[error("Failed to write audit event: {0}")]
    WriteError(String),
    #[error("Failed to read audit log: {0}")]
    ReadError(String),
    #[error("Export failed: {0}")]
    ExportError(String),
    #[error("Invalid log format: {0}")]
    InvalidFormat(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
