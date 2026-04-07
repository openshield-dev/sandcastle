//! Violation tracking — aggregate and query policy breaches within a session.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::event::EventType;

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// How serious a policy violation is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ViolationSeverity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for ViolationSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// Violation record
// ---------------------------------------------------------------------------

/// A single policy violation extracted from an audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// When the violation occurred.
    pub timestamp: DateTime<Utc>,
    /// The type of event that triggered the violation.
    pub event_type: EventType,
    /// Short human-readable summary.
    pub description: String,
    /// How severe the violation is.
    pub severity: ViolationSeverity,
    /// Name of the policy rule that was violated, if known.
    pub rule_name: Option<String>,
    /// Extended detail (e.g., the blocked path or domain).
    pub details: String,
}

impl Violation {
    /// Construct a violation record.
    pub fn new(
        event_type: EventType,
        description: impl Into<String>,
        severity: ViolationSeverity,
        details: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type,
            description: description.into(),
            severity,
            rule_name: None,
            details: details.into(),
        }
    }

    /// Attach a rule name to this violation.
    pub fn with_rule(mut self, rule: impl Into<String>) -> Self {
        self.rule_name = Some(rule.into());
        self
    }
}

// ---------------------------------------------------------------------------
// ViolationSummary
// ---------------------------------------------------------------------------

/// Aggregated statistics for a set of violations.
#[derive(Debug, Serialize, Deserialize)]
pub struct ViolationSummary {
    pub total: usize,
    pub critical: usize,
    pub warnings: usize,
    pub info: usize,
    /// The `EventType` string that appeared most often, if any.
    pub most_common_type: Option<String>,
}

// ---------------------------------------------------------------------------
// ViolationTracker
// ---------------------------------------------------------------------------

/// Accumulates [`Violation`]s for a sandbox session and provides query helpers.
#[derive(Debug, Default)]
pub struct ViolationTracker {
    violations: Vec<Violation>,
}

impl ViolationTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self {
            violations: Vec::new(),
        }
    }

    /// Append a violation.
    pub fn record(&mut self, violation: Violation) {
        self.violations.push(violation);
    }

    /// All recorded violations in insertion order.
    pub fn violations(&self) -> &[Violation] {
        &self.violations
    }

    /// Violations filtered to exactly the given severity level.
    pub fn by_severity(&self, severity: ViolationSeverity) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.severity == severity)
            .collect()
    }

    /// Total number of violations.
    pub fn count(&self) -> usize {
        self.violations.len()
    }

    /// `true` if any violation has `Critical` severity.
    pub fn has_critical(&self) -> bool {
        self.violations
            .iter()
            .any(|v| v.severity == ViolationSeverity::Critical)
    }

    /// Build a summary of all violations.
    pub fn summary(&self) -> ViolationSummary {
        let critical = self
            .violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Critical)
            .count();
        let warnings = self
            .violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Warning)
            .count();
        let info = self
            .violations
            .iter()
            .filter(|v| v.severity == ViolationSeverity::Info)
            .count();

        // Tally event types to find the most common.
        let mut type_counts: HashMap<String, usize> = HashMap::new();
        for v in &self.violations {
            *type_counts
                .entry(v.event_type.to_string())
                .or_insert(0) += 1;
        }
        let most_common_type = type_counts
            .into_iter()
            .max_by_key(|(_, n)| *n)
            .map(|(t, _)| t);

        ViolationSummary {
            total: self.violations.len(),
            critical,
            warnings,
            info,
            most_common_type,
        }
    }
}
