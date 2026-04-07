//! Export audit events to JSON, JSONL, CSV, or human-readable text.

use std::io::Write;
use std::path::Path;

use crate::error::AuditError;
use crate::event::{AuditEvent, PolicyDecision};

// ---------------------------------------------------------------------------
// Format enum
// ---------------------------------------------------------------------------

/// Supported export formats.
#[derive(Debug, Clone)]
pub enum ExportFormat {
    /// A single JSON array of events.
    Json,
    /// Newline-delimited JSON (one object per line).
    Jsonl,
    /// Comma-separated values with a header row.
    Csv,
    /// Human-readable text, one line per event.
    Text,
}

// ---------------------------------------------------------------------------
// AuditExporter
// ---------------------------------------------------------------------------

/// Stateless helper for rendering audit events in various formats.
pub struct AuditExporter;

impl AuditExporter {
    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Serialise `events` and write to the file at `path`.
    ///
    /// The file is created (or truncated) before writing.
    pub fn export_to_file(
        events: &[AuditEvent],
        path: &Path,
        format: ExportFormat,
    ) -> Result<(), AuditError> {
        let content = Self::export_to_string(events, format)?;
        let mut file = std::fs::File::create(path)?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    /// Serialise `events` to an in-memory `String`.
    pub fn export_to_string(
        events: &[AuditEvent],
        format: ExportFormat,
    ) -> Result<String, AuditError> {
        match format {
            ExportFormat::Json => Self::to_json(events),
            ExportFormat::Jsonl => Self::to_jsonl(events),
            ExportFormat::Csv => Self::to_csv(events),
            ExportFormat::Text => Ok(Self::to_text(events)),
        }
    }

    /// Format a single event as a one-line human-readable string.
    pub fn format_event(event: &AuditEvent) -> String {
        let ts = event.timestamp.format("%Y-%m-%dT%H:%M:%SZ");
        let decision = &event.policy_result.decision;
        let kind = &event.event_type;
        let desc = &event.action.description;
        format!("[{ts}] [{decision}] {kind}: {desc}  (sandbox={}, session={})",
            event.sandbox_id, event.session_id)
    }

    /// Render a multi-line summary table for a slice of events.
    pub fn format_summary(events: &[AuditEvent]) -> String {
        if events.is_empty() {
            return "No audit events recorded.".to_owned();
        }

        let total = events.len();
        let allowed = events
            .iter()
            .filter(|e| e.policy_result.decision == PolicyDecision::Allow)
            .count();
        let denied = events
            .iter()
            .filter(|e| e.policy_result.decision == PolicyDecision::Deny)
            .count();
        let ask = events
            .iter()
            .filter(|e| e.policy_result.decision == PolicyDecision::AskHuman)
            .count();
        let audit_only = events
            .iter()
            .filter(|e| e.policy_result.decision == PolicyDecision::AuditOnly)
            .count();

        // Per-event-type breakdown.
        use std::collections::HashMap;
        let mut by_type: HashMap<String, usize> = HashMap::new();
        for e in events {
            *by_type.entry(e.event_type.to_string()).or_insert(0) += 1;
        }
        let mut type_rows: Vec<(String, usize)> = by_type.into_iter().collect();
        type_rows.sort_by(|a, b| b.1.cmp(&a.1));

        let mut out = String::new();
        out.push_str("=== Audit Summary ===\n");
        out.push_str(&format!("  Total events : {total}\n"));
        out.push_str(&format!("  Allowed      : {allowed}\n"));
        out.push_str(&format!("  Denied       : {denied}\n"));
        out.push_str(&format!("  Ask-human    : {ask}\n"));
        out.push_str(&format!("  Audit-only   : {audit_only}\n"));
        out.push_str("\n  By event type:\n");
        for (t, n) in &type_rows {
            out.push_str(&format!("    {t:<28} {n}\n"));
        }
        out
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    fn to_json(events: &[AuditEvent]) -> Result<String, AuditError> {
        serde_json::to_string_pretty(events).map_err(AuditError::Json)
    }

    fn to_jsonl(events: &[AuditEvent]) -> Result<String, AuditError> {
        let mut out = String::new();
        for event in events {
            let line = serde_json::to_string(event)?;
            out.push_str(&line);
            out.push('\n');
        }
        Ok(out)
    }

    fn to_csv(events: &[AuditEvent]) -> Result<String, AuditError> {
        let mut out =
            String::from("id,timestamp,sandbox_id,session_id,event_type,decision,description\n");
        for e in events {
            // Escape any commas or quotes in the description.
            let desc = e.action.description.replace('"', "\"\"");
            out.push_str(&format!(
                "{},{},{},{},{},{},\"{}\"\n",
                e.id,
                e.timestamp.to_rfc3339(),
                e.sandbox_id,
                e.session_id,
                e.event_type,
                e.policy_result.decision,
                desc,
            ));
        }
        Ok(out)
    }

    fn to_text(events: &[AuditEvent]) -> String {
        events
            .iter()
            .map(Self::format_event)
            .collect::<Vec<_>>()
            .join("\n")
    }
}
