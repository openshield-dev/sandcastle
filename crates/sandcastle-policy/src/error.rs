//! Error types for policy parsing and validation.

use thiserror::Error;

/// Errors that can occur while loading or validating a [`super::SandboxProfile`].
#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("profile not found: {0}")]
    ProfileNotFound(String),

    #[error("invalid permission specification: {0}")]
    InvalidPermission(String),

    #[error("policy conflict: {0}")]
    PolicyConflict(String),

    #[error("failed to parse policy file: {0}")]
    ParseError(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),
}
