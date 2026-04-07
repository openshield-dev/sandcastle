//! Read audit events back from a JSONL log file.

use std::io::BufRead;
use std::path::Path;

use crate::error::AuditError;
use crate::event::AuditEvent;

/// Stateless helper for reading [`AuditEvent`]s from a JSONL audit log.
pub struct AuditStore;

impl AuditStore {
    /// Read **all** events from `path`.
    ///
    /// Lines that fail to parse are skipped with an `InvalidFormat` error
    /// returned for the first bad line encountered; earlier valid events are
    /// still returned by the caller.  If you need strict validation use
    /// [`Self::read_all`] and treat any `Err` as fatal.
    pub fn read_all(path: &Path) -> Result<Vec<AuditEvent>, AuditError> {
        Self::parse_lines(path, None)
    }

    /// Read the **last `n`** events from `path`.
    ///
    /// This reads the whole file (JSONL has no index) and returns the tail.
    pub fn read_last(path: &Path, n: usize) -> Result<Vec<AuditEvent>, AuditError> {
        let all = Self::parse_lines(path, None)?;
        let skip = all.len().saturating_sub(n);
        Ok(all.into_iter().skip(skip).collect())
    }

    /// Read only events where the policy decision was `Deny` or `AskHuman`.
    pub fn read_violations(path: &Path) -> Result<Vec<AuditEvent>, AuditError> {
        let all = Self::parse_lines(path, None)?;
        Ok(all.into_iter().filter(|e| e.is_violation()).collect())
    }

    /// Count the number of valid event lines without deserialising every field.
    pub fn count_events(path: &Path) -> Result<u64, AuditError> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let mut count: u64 = 0;
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Validate that the line is at least parseable JSON before counting.
            serde_json::from_str::<serde_json::Value>(trimmed)
                .map_err(|e| AuditError::InvalidFormat(e.to_string()))?;
            count += 1;
        }
        Ok(count)
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Parse JSONL lines, optionally stopping after `limit` events.
    fn parse_lines(path: &Path, limit: Option<usize>) -> Result<Vec<AuditEvent>, AuditError> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        let mut events = Vec::new();

        for (i, line_result) in reader.lines().enumerate() {
            if let Some(max) = limit {
                if i >= max {
                    break;
                }
            }
            let line = line_result?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let event: AuditEvent = serde_json::from_str(trimmed)
                .map_err(|e| AuditError::InvalidFormat(format!("line {}: {e}", i + 1)))?;
            events.push(event);
        }

        Ok(events)
    }
}
