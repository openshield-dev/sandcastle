//! Structured audit logging and event recording for all SandCastle sandbox operations.
//!
//! Every action taken by or on behalf of a sandboxed agent — file access, network
//! connection, process spawn, snapshot — is recorded as an [`AuditEvent`]. Events
//! are serialised as newline-delimited JSON for easy ingestion by log aggregators.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use sandcastle_audit::event::{AuditEvent, EventType, PolicyDecision};
//! use sandcastle_audit::logger::{AuditLogger, StdoutAuditSink};
//! use uuid::Uuid;
//!
//! let session = Uuid::new_v4();
//! let event = AuditEvent::filesystem(
//!     "sandbox-1".to_owned(),
//!     session,
//!     EventType::FilesystemRead,
//!     "/etc/passwd".to_owned(),
//!     PolicyDecision::Deny,
//! );
//!
//! let mut logger = AuditLogger::new();
//! logger.add_sink(Box::new(StdoutAuditSink));
//! logger.log(event).unwrap();
//! ```

pub mod error;
pub mod event;
pub mod export;
pub mod logger;
pub mod store;
pub mod violation;

// ---------------------------------------------------------------------------
// Top-level re-exports for the most commonly used types.
// ---------------------------------------------------------------------------

/// The core audit event type.
pub use event::AuditEvent;
/// Backward-compatible alias — `EventKind` is now `EventType`.
pub use event::EventKind;
/// The multi-sink logger.
pub use logger::AuditLogger;
