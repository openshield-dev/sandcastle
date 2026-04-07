//! Error types for filesystem isolation operations.

use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FsError {
    #[error("mount failed for {path}: {reason}")]
    MountFailed { path: PathBuf, reason: String },

    #[error("path not allowed: {0}")]
    PathDenied(PathBuf),

    #[error("overlay setup failed: {0}")]
    OverlayError(String),

    #[error("copy-on-write error: {0}")]
    CowError(String),

    #[error("tmpfs error: {0}")]
    TmpfsError(String),

    #[error("isolation teardown failed: {0}")]
    TeardownError(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
