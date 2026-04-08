#![forbid(unsafe_code)]
//! Network isolation, egress filtering, and DNS control for SandCastle sandboxes.
//!
//! This crate provides:
//! - [`dns`]: DNS interception with allowlist/blocklist enforcement.
//! - [`allowlist`]: Domain allowlist management with glob patterns.
//! - [`egress`]: Egress control — rate limiting and bandwidth caps.
//! - [`tls`]: TLS SNI verification and minimum-version enforcement.
//! - [`filter`]: High-level [`NetworkFilter`] that orchestrates all of the above.

pub mod allowlist;
pub mod dns;
pub mod egress;
pub mod error;
pub mod filter;
pub mod tls;

pub use allowlist::DomainAllowlist;
pub use dns::DnsInterceptor;
pub use egress::EgressController;
pub use error::NetworkError;
pub use filter::{NetworkFilter, NetworkStats};
pub use tls::TlsVerifier;
