//! Audit logger — collects [`AuditEvent`]s and fans them out to one or more sinks.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use tracing::info;

use crate::error::AuditError;
use crate::event::{AuditEvent, PolicyDecision};

// ---------------------------------------------------------------------------
// Sink trait
// ---------------------------------------------------------------------------

/// A destination that receives audit events.
///
/// Implementations must be `Send + Sync` so they can be shared across threads.
pub trait AuditSink: Send + Sync {
    /// Write a single event to the sink.
    fn write_event(&self, event: &AuditEvent) -> Result<(), AuditError>;
    /// Flush any buffered data to the underlying storage.
    fn flush(&self) -> Result<(), AuditError>;
}

// ---------------------------------------------------------------------------
// File sink (JSONL)
// ---------------------------------------------------------------------------

/// Writes audit events as newline-delimited JSON to a file.
pub struct FileAuditSink {
    writer: Mutex<std::io::BufWriter<std::fs::File>>,
    path: PathBuf,
}

impl FileAuditSink {
    /// Open (or create) the file at `path` for append-only writing.
    pub fn new(path: PathBuf) -> Result<Self, AuditError> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            writer: Mutex::new(std::io::BufWriter::new(file)),
            path,
        })
    }

    /// Return the path this sink writes to.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl AuditSink for FileAuditSink {
    fn write_event(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let line = serde_json::to_string(event)?;
        let mut w = self
            .writer
            .lock()
            .map_err(|e| AuditError::WriteError(e.to_string()))?;
        writeln!(w, "{line}").map_err(AuditError::Io)
    }

    fn flush(&self) -> Result<(), AuditError> {
        let mut w = self
            .writer
            .lock()
            .map_err(|e| AuditError::WriteError(e.to_string()))?;
        w.flush().map_err(AuditError::Io)
    }
}

// ---------------------------------------------------------------------------
// Stdout sink (debugging)
// ---------------------------------------------------------------------------

/// Prints audit events to stdout as formatted JSON — useful during development.
pub struct StdoutAuditSink;

impl AuditSink for StdoutAuditSink {
    fn write_event(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let line = serde_json::to_string(event)?;
        println!("{line}");
        Ok(())
    }

    fn flush(&self) -> Result<(), AuditError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tracing sink (integrates with the `tracing` ecosystem)
// ---------------------------------------------------------------------------

/// Forwards audit events to the active `tracing` subscriber.
pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn write_event(&self, event: &AuditEvent) -> Result<(), AuditError> {
        info!(
            event_id  = %event.id,
            sandbox   = %event.sandbox_id,
            session   = %event.session_id,
            kind      = %event.event_type,
            decision  = %event.policy_result.decision,
            detail    = %event.action.description,
            "audit"
        );
        Ok(())
    }

    fn flush(&self) -> Result<(), AuditError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AuditLogger
// ---------------------------------------------------------------------------

/// Central audit logger.
///
/// Receives [`AuditEvent`]s and fans them out to every registered [`AuditSink`].
/// Tracks running totals for events and policy violations.
///
/// # Example
///
/// ```rust,no_run
/// use sandcastle_audit::logger::{AuditLogger, StdoutAuditSink};
///
/// let mut logger = AuditLogger::new();
/// logger.add_sink(Box::new(StdoutAuditSink));
/// ```
pub struct AuditLogger {
    sinks: Vec<Box<dyn AuditSink>>,
    event_count: u64,
    violation_count: u64,
}

impl AuditLogger {
    /// Create an empty logger with no sinks.
    pub fn new() -> Self {
        Self {
            sinks: Vec::new(),
            event_count: 0,
            violation_count: 0,
        }
    }

    /// Register an additional sink.
    pub fn add_sink(&mut self, sink: Box<dyn AuditSink>) {
        self.sinks.push(sink);
    }

    /// Submit an event to all registered sinks.
    ///
    /// Errors from individual sinks are collected; the first error encountered
    /// is returned after attempting every sink.
    pub fn log(&mut self, event: AuditEvent) -> Result<(), AuditError> {
        if event.is_violation() {
            self.violation_count += 1;
        }
        self.event_count += 1;

        let mut first_error: Option<AuditError> = None;
        for sink in &self.sinks {
            if let Err(e) = sink.write_event(&event) {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }

        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Total number of events logged (including violations).
    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Total number of events that represented policy violations.
    pub fn violation_count(&self) -> u64 {
        self.violation_count
    }

    /// Flush all sinks.
    pub fn flush_all(&self) -> Result<(), AuditError> {
        let mut first_error: Option<AuditError> = None;
        for sink in &self.sinks {
            if let Err(e) = sink.flush() {
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    // ------------------------------------------------------------------
    // Backward-compatible helper kept from the original minimal logger
    // ------------------------------------------------------------------

    /// Record an event via the tracing subscriber (no sinks required).
    ///
    /// This is the original single-method API retained for callers that
    /// haven't migrated to the full sink-based interface.
    pub fn record(&self, event: &AuditEvent) {
        info!(
            event_id  = %event.id,
            sandbox   = %event.sandbox_id,
            kind      = %event.event_type,
            allowed   = event.policy_result.decision == PolicyDecision::Allow,
            detail    = %event.action.description,
            "audit"
        );
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}
