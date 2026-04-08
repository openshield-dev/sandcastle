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
    /// Write a pre-serialized JSON line (enriched with sequence number).
    fn write_line(&self, json_line: &str) -> Result<(), AuditError>;
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
    ///
    /// On Unix the file permissions are set to `0o600` (owner read/write only)
    /// so that other users on the system cannot read sensitive audit data.
    pub fn new(path: PathBuf) -> Result<Self, AuditError> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms)?;
        }

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
        self.write_line(&line)
    }

    fn write_line(&self, json_line: &str) -> Result<(), AuditError> {
        let mut w = match self.writer.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        writeln!(w, "{json_line}").map_err(AuditError::Io)
    }

    fn flush(&self) -> Result<(), AuditError> {
        let mut w = match self.writer.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
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
        self.write_line(&line)
    }

    fn write_line(&self, json_line: &str) -> Result<(), AuditError> {
        println!("{json_line}");
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

    fn write_line(&self, json_line: &str) -> Result<(), AuditError> {
        info!(json = %json_line, "audit");
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
/// Default maximum events allowed per minute before rate-limiting kicks in.
const DEFAULT_MAX_EVENTS_PER_MINUTE: u64 = 10_000;

/// Default maximum approximate file size in bytes (100 MB).
const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 100_000_000;

/// Average estimated size of a single serialised audit event (bytes).
const AVG_EVENT_SIZE: u64 = 512;

pub struct AuditLogger {
    sinks: Vec<Box<dyn AuditSink>>,
    event_count: u64,
    violation_count: u64,
    /// Monotonically increasing sequence number included in every logged event.
    sequence_number: u64,
    /// Maximum events allowed per minute.
    max_events_per_minute: u64,
    /// Maximum approximate file size in bytes.
    max_file_size_bytes: u64,
    /// Event count within the current rate-limit window.
    current_minute_count: u64,
    /// Start of the current rate-limit window (Unix timestamp in seconds).
    current_minute_start: u64,
    /// Whether a rate-limit warning has already been emitted for this window.
    rate_limit_warned: bool,
    /// Whether a size-limit warning has already been emitted.
    size_limit_warned: bool,
}

impl AuditLogger {
    /// Create an empty logger with no sinks.
    pub fn new() -> Self {
        Self {
            sinks: Vec::new(),
            event_count: 0,
            violation_count: 0,
            sequence_number: 0,
            max_events_per_minute: DEFAULT_MAX_EVENTS_PER_MINUTE,
            max_file_size_bytes: DEFAULT_MAX_FILE_SIZE_BYTES,
            current_minute_count: 0,
            current_minute_start: 0,
            rate_limit_warned: false,
            size_limit_warned: false,
        }
    }

    /// Set the maximum number of events allowed per minute.
    pub fn set_max_events_per_minute(&mut self, max: u64) {
        self.max_events_per_minute = max;
    }

    /// Set the maximum approximate file size in bytes.
    pub fn set_max_file_size_bytes(&mut self, max: u64) {
        self.max_file_size_bytes = max;
    }

    /// Register an additional sink.
    pub fn add_sink(&mut self, sink: Box<dyn AuditSink>) {
        self.sinks.push(sink);
    }

    /// Submit an event to all registered sinks.
    ///
    /// The event is enriched with a monotonic sequence number (`seq` field in
    /// JSON output) so that consumers can detect gaps caused by deleted records.
    ///
    /// Rate-limiting and approximate size-limiting are enforced: when the limit
    /// is hit a single warning is logged via `tracing` and subsequent events in
    /// the same window are silently dropped.
    ///
    /// Errors from individual sinks are collected; the first error encountered
    /// is returned after attempting every sink.
    pub fn log(&mut self, event: AuditEvent) -> Result<(), AuditError> {
        // --- Rate limiting (per-minute window) ---
        let now_secs = event.timestamp.timestamp() as u64;
        if now_secs / 60 != self.current_minute_start / 60 {
            // New minute window — reset counters.
            self.current_minute_start = now_secs;
            self.current_minute_count = 0;
            self.rate_limit_warned = false;
        }
        self.current_minute_count = self.current_minute_count.saturating_add(1);
        if self.current_minute_count > self.max_events_per_minute {
            if !self.rate_limit_warned {
                tracing::warn!(
                    "audit rate limit exceeded ({} events/min) — dropping events",
                    self.max_events_per_minute,
                );
                self.rate_limit_warned = true;
            }
            return Ok(());
        }

        // --- Approximate size limiting ---
        let approx_size = self.event_count.saturating_mul(AVG_EVENT_SIZE);
        if approx_size >= self.max_file_size_bytes {
            if !self.size_limit_warned {
                tracing::warn!(
                    "audit log approximate size limit reached ({} bytes) — dropping events",
                    self.max_file_size_bytes,
                );
                self.size_limit_warned = true;
            }
            return Ok(());
        }

        // --- Assign sequence number ---
        let seq = self.sequence_number;
        self.sequence_number = self.sequence_number.saturating_add(1);

        // --- Build the enriched JSON value with sequence number ---
        let mut value = serde_json::to_value(&event)?;
        if let Some(obj) = value.as_object_mut() {
            obj.insert("seq".to_owned(), serde_json::Value::from(seq));
        }

        // --- Update counters (saturating to prevent overflow) ---
        if event.is_violation() {
            self.violation_count = self.violation_count.saturating_add(1);
        }
        self.event_count = self.event_count.saturating_add(1);

        // Write enriched JSON (with seq number) to sinks instead of raw event.
        let enriched_line = serde_json::to_string(&value)?;
        let mut first_error: Option<AuditError> = None;
        for sink in &self.sinks {
            if let Err(e) = sink.write_line(&enriched_line) {
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

    /// Return the current sequence number (next event will receive this value).
    pub fn sequence_number(&self) -> u64 {
        self.sequence_number
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
