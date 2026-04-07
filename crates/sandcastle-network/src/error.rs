//! Error types for network isolation operations.

use thiserror::Error;

/// Errors produced by the network isolation layer.
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("connection to {domain} denied by policy")]
    Denied { domain: String },

    #[error("DNS resolution failed for {domain}: {reason}")]
    DnsError { domain: String, reason: String },

    #[error("failed to apply network filter: {0}")]
    FilterFailed(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
