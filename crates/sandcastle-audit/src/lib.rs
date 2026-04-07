//! Structured audit logging and event recording for all SandCastle sandbox operations.
//!
//! Every action taken by or on behalf of a sandboxed agent — file access, network
//! connection, process spawn, snapshot — is recorded as an [`AuditEvent`]. Events
//! are serialised as newline-delimited JSON for easy ingestion by log aggregators.

pub mod event;
pub mod logger;

pub use event::{AuditEvent, EventKind};
pub use logger::AuditLogger;
