//! CLI command that displays a risk score report after a sandbox run.

use std::collections::HashMap;

use anyhow::Context;
use sandcastle_audit::event::AuditEvent;
use sandcastle_audit::risk::RiskReport;

const DEFAULT_LOG_PATH: &str = ".sandcastle/audit.log";
const DEFAULT_THRESHOLD: u8 = 7;

/// Execute the `sandcastle risk` command.
///
/// Reads audit events, filters to the given session (or latest), and prints
/// a formatted risk report.
pub fn execute(audit_file: Option<&str>, session_id: Option<&str>) -> anyhow::Result<()> {
    let events = load_events(audit_file, session_id)?;
    let report = RiskReport::from_events(&events);
    print_report(&report);
    Ok(())
}

/// Returns `true` if the score is within `max_score`, `false` otherwise.
/// Intended for CI: the caller can map `false` to exit-code 1.
pub fn execute_with_threshold(
    audit_file: Option<&str>,
    session_id: Option<&str>,
    max_score: u8,
) -> anyhow::Result<bool> {
    let events = load_events(audit_file, session_id)?;
    let report = RiskReport::from_events(&events);
    print_report(&report);

    let max = if max_score > 10 { DEFAULT_THRESHOLD } else { max_score };
    if report.score > max {
        println!();
        println!(
            "  FAIL: risk score {}/10 exceeds threshold {}/10",
            report.score, max
        );
        Ok(false)
    } else {
        Ok(true)
    }
}

/// Read and parse audit events, optionally filtering to a single session.
fn load_events(
    audit_file: Option<&str>,
    session_id: Option<&str>,
) -> anyhow::Result<Vec<AuditEvent>> {
    let log_path = match audit_file {
        Some(f) => std::path::PathBuf::from(f),
        None => std::env::current_dir()
            .context("Failed to determine current directory")?
            .join(DEFAULT_LOG_PATH),
    };

    if !log_path.exists() {
        anyhow::bail!(
            "No audit log found at {}. Run `sandcastle run` first.",
            log_path.display()
        );
    }

    let raw = std::fs::read_to_string(&log_path)
        .with_context(|| format!("Failed to read audit log '{}'", log_path.display()))?;

    let mut events: Vec<AuditEvent> = Vec::new();
    let mut parse_failures: usize = 0;
    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<AuditEvent>(line) {
            Ok(ev) => events.push(ev),
            Err(_) => parse_failures += 1,
        }
    }

    if parse_failures > 0 {
        eprintln!("Warning: {parse_failures} line(s) could not be parsed");
    }

    if events.is_empty() {
        anyhow::bail!("Audit log is empty or contains no valid events.");
    }

    // Filter by session: explicit id, or auto-detect the latest session.
    let target_session = match session_id {
        Some(id) => id.to_string(),
        None => latest_session(&events),
    };

    events.retain(|e| e.session_id.to_string() == target_session);

    if events.is_empty() {
        anyhow::bail!("No events found for session {target_session}");
    }

    Ok(events)
}

/// Find the session with the most recent event timestamp.
fn latest_session(events: &[AuditEvent]) -> String {
    let mut latest: HashMap<String, chrono::DateTime<chrono::Utc>> = HashMap::new();
    for e in events {
        let sid = e.session_id.to_string();
        latest.entry(sid).and_modify(|ts| { if e.timestamp > *ts { *ts = e.timestamp; } }).or_insert(e.timestamp);
    }
    latest.into_iter().max_by_key(|(_, ts)| *ts).map(|(s, _)| s).unwrap_or_default()
}

fn print_report(report: &RiskReport) {
    println!("\u{2500}\u{2500}\u{2500} SandCastle Risk Report \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");
    println!("  Risk Score: {}/10 ({})\n", report.score, report.level);

    if !report.factors.is_empty() {
        println!("  Risk Factors:");
        let last = report.factors.len() - 1;
        for (i, f) in report.factors.iter().enumerate() {
            let c = if i < last { "\u{251c}\u{2500}" } else { "\u{2514}\u{2500}" };
            println!("  {} +{:<2} {}", c, f.points, f.description);
        }
        println!();
    }

    // Safe indicators: absence of certain risk factor categories.
    let indicators: &[(&str, &str)] = &[
        ("sensitive_file_access", "No sensitive files accessed"),
        ("unknown_network_domains", "All network destinations allowlisted"),
        ("file_deletion", "No file deletions"),
        ("env_var_access", "No environment variable access"),
    ];
    let safe: Vec<&str> = indicators.iter()
        .filter(|(name, _)| !report.factors.iter().any(|f| f.name == *name))
        .map(|(_, msg)| *msg)
        .collect();

    if !safe.is_empty() {
        println!("  Safe Indicators:");
        let last = safe.len() - 1;
        for (i, msg) in safe.iter().enumerate() {
            let c = if i < last { "\u{251c}\u{2500}" } else { "\u{2514}\u{2500}" };
            println!("  {} \u{2713} {}", c, msg);
        }
        println!();
    }

    println!("  Recommendation: {}", report.summary);
    println!("\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");
}
