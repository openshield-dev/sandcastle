//! Risk scoring engine that quantifies the security risk of each sandbox run.

use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use crate::event::{AuditEvent, EventType, PolicyDecision};

/// Risk assessment for a single sandbox run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskReport {
    /// Overall risk score (0-10, where 0 = safe, 10 = critical).
    pub score: u8,
    /// Human-readable risk level.
    pub level: RiskLevel,
    /// Individual risk factors that contributed to the score.
    pub factors: Vec<RiskFactor>,
    /// Summary sentence.
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel { Safe, Low, Medium, High, Critical }

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Safe => "Safe", Self::Low => "Low", Self::Medium => "Medium",
            Self::High => "High", Self::Critical => "Critical",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor { pub name: String, pub points: u8, pub description: String }

const ALLOWLISTED: &[&str] = &[
    "github.com", "api.github.com", "pypi.org", "files.pythonhosted.org",
    "registry.npmjs.org", "npmjs.com", "crates.io", "rubygems.org",
    "maven.org", "docker.io", "registry.hub.docker.com", "stackoverflow.com", "docs.rs",
];
const SENSITIVE: &[&str] = &[
    ".ssh", ".aws", ".gnupg", ".env", "credentials", "private_key", "id_rsa", "id_ed25519",
];
const METADATA: &[&str] = &["169.254.169.254", "metadata.google.internal"];

/// Helper to push a factor and accumulate score.
fn add(factors: &mut Vec<RiskFactor>, raw: &mut u16, name: &str, pts: u8, desc: String) {
    factors.push(RiskFactor { name: name.into(), points: pts, description: desc });
    *raw += u16::from(pts);
}

fn path_matches(e: &AuditEvent, patterns: &[&str]) -> bool {
    e.action.path.as_deref().map_or(false, |p| {
        let lo = p.to_lowercase();
        patterns.iter().any(|s| lo.contains(s))
    })
}

impl RiskReport {
    /// Build a risk report by analysing a slice of audit events.
    pub fn from_events(events: &[AuditEvent]) -> Self {
        let mut factors = Vec::new();
        let mut raw: u16 = 0;

        // Sensitive file access (+3)
        let sens = events.iter().filter(|e| path_matches(e, SENSITIVE)).count();
        if sens > 0 { add(&mut factors, &mut raw, "sensitive_file_access", 3, format!("{sens} sensitive file(s) accessed")); }

        // Blocked operations (+1 per 5, min 1)
        let blocked = events.iter().filter(|e| e.policy_result.decision == PolicyDecision::Deny).count();
        if blocked > 0 {
            let pts = (blocked / 5).max(1).min(10) as u8;
            add(&mut factors, &mut raw, "blocked_operations", pts, format!("{blocked} blocked operation(s)"));
        }

        // Network to unknown domains (+2)
        let domains: HashSet<&str> = events.iter()
            .filter(|e| matches!(e.event_type, EventType::NetworkConnect | EventType::NetworkRequest))
            .filter_map(|e| e.action.domain.as_deref()).collect();
        let unknown: Vec<&str> = domains.iter().copied().filter(|d| !ALLOWLISTED.contains(d)).collect();
        if !unknown.is_empty() { add(&mut factors, &mut raw, "unknown_network_domains", 2, format!("{} unknown domain(s)", unknown.len())); }

        // Cloud metadata access (+4)
        let meta = events.iter().any(|e| {
            e.action.domain.as_deref().map_or(false, |d| METADATA.contains(&d))
                || path_matches(e, METADATA)
        });
        if meta { add(&mut factors, &mut raw, "cloud_metadata_access", 4, "attempted access to cloud metadata endpoint".into()); }

        // Process execution (+1 per unique)
        let procs: HashSet<&str> = events.iter()
            .filter(|e| matches!(e.event_type, EventType::ProcessExec | EventType::ProcessSpawn))
            .filter_map(|e| e.action.command.as_deref()).collect();
        if !procs.is_empty() { add(&mut factors, &mut raw, "process_execution", (procs.len() as u8).min(10), format!("{} unique process(es) spawned", procs.len())); }

        // Environment variable access (+2)
        let env = events.iter().any(|e| e.action.description.to_lowercase().contains("env") || e.action.extra.contains_key("env_var"));
        if env { add(&mut factors, &mut raw, "env_var_access", 2, "environment variable access detected".into()); }

        // High event volume (+1)
        if events.len() > 500 { add(&mut factors, &mut raw, "high_event_volume", 1, format!("{} events in session (>500)", events.len())); }

        // File deletion (+2)
        let dels = events.iter().filter(|e| e.event_type == EventType::FilesystemDelete).count();
        if dels > 0 { add(&mut factors, &mut raw, "file_deletion", 2, format!("{dels} file deletion(s)")); }

        // Write outside project dir (+3)
        let outside = events.iter()
            .filter(|e| e.event_type == EventType::FilesystemWrite)
            .filter(|e| e.action.extra.get("outside_project").and_then(|v| v.as_bool()).unwrap_or(false))
            .count();
        if outside > 0 { add(&mut factors, &mut raw, "write_outside_project", 3, format!("{outside} write(s) outside project directory")); }

        let score = (raw as u8).min(10);
        let level = RiskLevel::from_score(score);
        let summary = Self::build_summary(&level, sens, &domains, &unknown, blocked, dels);
        Self { score, level, factors, summary }
    }

    fn build_summary(level: &RiskLevel, sens: usize, all_dom: &HashSet<&str>, unk: &[&str], blocked: usize, dels: usize) -> String {
        let mut p = Vec::new();
        p.push(if sens > 0 { format!("{sens} sensitive file(s) accessed") } else { "no sensitive files accessed".into() });
        p.push(if all_dom.is_empty() { "no network activity".into() }
               else if unk.is_empty() { "all network destinations allowlisted".into() }
               else { format!("{} unknown network destination(s)", unk.len()) });
        if blocked > 0 { p.push(format!("{blocked} blocked request(s)")); }
        if dels > 0 { p.push(format!("{dels} file deletion(s)")); }
        format!("{level}: {}", p.join(", "))
    }

    /// Print a formatted risk report to stdout.
    pub fn display_formatted(&self) {
        let fval = |name: &str| -> usize {
            self.factors.iter().find(|f| f.name == name)
                .and_then(|f| f.description.split_whitespace().next()?.parse().ok()).unwrap_or(0)
        };
        let has_del = self.factors.iter().any(|f| f.name == "file_deletion");
        let has_unk = self.factors.iter().find(|f| f.name == "unknown_network_domains");

        println!("sandcastle: run complete");
        println!("  Risk score: {}/10 ({})", self.score, self.level);
        println!("  \u{251c}\u{2500} {} sensitive files accessed", fval("sensitive_file_access"));
        if let Some(d) = has_unk {
            println!("  \u{251c}\u{2500} {}", d.description);
        } else {
            println!("  \u{251c}\u{2500} network domains (all allowlisted)");
        }
        println!("  \u{251c}\u{2500} {} blocked operation(s)", fval("blocked_operations"));
        println!("  \u{2514}\u{2500} {}", if has_del { "File deletions detected" } else { "No file deletions" });
    }
}

impl RiskLevel {
    fn from_score(score: u8) -> Self {
        match score { 0..=2 => Self::Safe, 3..=4 => Self::Low, 5..=6 => Self::Medium, 7..=8 => Self::High, _ => Self::Critical }
    }
}
