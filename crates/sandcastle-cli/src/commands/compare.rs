//! Implementation of the `sandcastle compare` command.
//!
//! A/B testing of two agent commands — reads audit logs from two sessions and
//! prints a side-by-side comparison of what each one did.

use std::collections::HashMap;
use anyhow::Context;
use sandcastle_audit::event::{EventType, PolicyDecision};
use sandcastle_audit::AuditEvent;

/// Aggregated summary of a single run/session extracted from audit events.
struct RunSummary {
    #[allow(dead_code)] // Used in display formatting
    session_id: String,
    command: String,
    duration_secs: f64,
    files_read: usize,
    files_written: usize,
    files_created: usize,
    files_deleted: usize,
    network_domains: Vec<(String, u64)>,
    network_bytes: u64,
    processes_spawned: usize,
    blocked_operations: usize,
    total_events: usize,
}

/// Execute the `sandcastle compare` command.
///
/// Reads NDJSON audit events from two log files (one per run), summarises each
/// session, and prints a formatted comparison table.
pub fn execute(
    command_a: &[String],
    command_b: &[String],
    profile: &str,
) -> anyhow::Result<()> {
    let file_a = command_a
        .first()
        .context("Run A: expected at least one argument (audit log path)")?;
    let file_b = command_b
        .first()
        .context("Run B: expected at least one argument (audit log path)")?;

    let events_a = load_events(file_a)?;
    let events_b = load_events(file_b)?;

    if events_a.is_empty() {
        anyhow::bail!("Run A log '{}' contains no parseable audit events", file_a);
    }
    if events_b.is_empty() {
        anyhow::bail!("Run B log '{}' contains no parseable audit events", file_b);
    }

    let label_a = command_a.get(1).map_or("A", |s| s.as_str());
    let label_b = command_b.get(1).map_or("B", |s| s.as_str());
    let summary_a = summarize_session(&events_a, label_a);
    let summary_b = summarize_session(&events_b, label_b);

    print_comparison(&summary_a, &summary_b, profile);

    Ok(())
}

/// Load and parse NDJSON audit events from a file.
fn load_events(path: &str) -> anyhow::Result<Vec<AuditEvent>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read audit log '{path}'"))?;
    let mut events = Vec::new();
    for line in raw.lines().filter(|l| !l.trim().is_empty()) {
        if let Ok(ev) = serde_json::from_str::<AuditEvent>(line) {
            events.push(ev);
        }
    }
    Ok(events)
}

/// Build a [`RunSummary`] from a slice of audit events.
fn summarize_session(events: &[AuditEvent], label: &str) -> RunSummary {
    let session_id = events
        .first()
        .map(|e| e.session_id.to_string())
        .unwrap_or_default();

    let duration_secs = match (events.first(), events.last()) {
        (Some(first), Some(last)) => {
            last.timestamp.signed_duration_since(first.timestamp)
                .num_milliseconds().max(0) as f64 / 1000.0
        }
        _ => 0.0,
    };
    let (mut files_read, mut files_written, mut files_created, mut files_deleted) = (0, 0, 0, 0);
    let mut domain_counts: HashMap<String, u64> = HashMap::new();
    let mut network_bytes: u64 = 0;
    let mut processes_spawned: usize = 0;
    let mut blocked_operations: usize = 0;

    for ev in events {
        match ev.event_type {
            EventType::FilesystemRead => files_read += 1,
            EventType::FilesystemWrite => files_written += 1,
            EventType::FilesystemCreate => files_created += 1,
            EventType::FilesystemDelete => files_deleted += 1,
            EventType::NetworkConnect | EventType::NetworkRequest => {
                if let Some(ref domain) = ev.action.domain {
                    *domain_counts.entry(domain.clone()).or_default() += 1;
                }
                if let Some(sz) = ev.action.size_bytes {
                    network_bytes += sz;
                }
            }
            EventType::ProcessExec | EventType::ProcessSpawn => {
                processes_spawned += 1;
            }
            _ => {}
        }

        if ev.policy_result.decision == PolicyDecision::Deny {
            blocked_operations += 1;
        }
    }

    let mut network_domains: Vec<(String, u64)> = domain_counts.into_iter().collect();
    network_domains.sort_by(|a, b| b.1.cmp(&a.1));

    RunSummary {
        session_id,
        command: label.to_string(),
        duration_secs,
        files_read,
        files_written,
        files_created,
        files_deleted,
        network_domains,
        network_bytes,
        processes_spawned,
        blocked_operations,
        total_events: events.len(),
    }
}

fn fmt_duration(secs: f64) -> String {
    let total = secs as u64;
    let (m, s) = (total / 60, total % 60);
    if m > 0 { format!("{m}m {s:02}s") } else { format!("{s}s") }
}

fn fmt_bytes(bytes: u64) -> String {
    match bytes {
        0 => "0 B".to_string(),
        b if b < 1024 => format!("{b} B"),
        b if b < 1024 * 1024 => format!("{} KB", b / 1024),
        b => format!("{:.1} MB", b as f64 / (1024.0 * 1024.0)),
    }
}

/// Print the formatted side-by-side comparison table.
fn print_comparison(a: &RunSummary, b: &RunSummary, profile: &str) {
    let w_label = 17;
    let w_col = 14;
    let w_total = w_label + 1 + w_col + 1 + w_col + 1;

    println!();
    println!("{}", format!("─── SandCastle Compare ({profile}) ").pad_end(w_total, '─'));

    // Header
    println!("┌{:─<w_label$}┬{:─<w_col$}┬{:─<w_col$}┐", "", "", "");
    println!(
        "│{:<w_label$}│{:<w_col$}│{:<w_col$}│",
        "", " Run A", " Run B"
    );
    println!(
        "│{:<w_label$}│{:<w_col$}│{:<w_col$}│",
        "",
        format!(" {}", a.command),
        format!(" {}", b.command)
    );
    println!("├{:─<w_label$}┼{:─<w_col$}┼{:─<w_col$}┤", "", "", "");

    // Data rows
    let rows: Vec<(&str, String, String)> = vec![
        ("Duration", fmt_duration(a.duration_secs), fmt_duration(b.duration_secs)),
        ("Files read", a.files_read.to_string(), b.files_read.to_string()),
        ("Files written", a.files_written.to_string(), b.files_written.to_string()),
        ("Files created", a.files_created.to_string(), b.files_created.to_string()),
        ("Files deleted", a.files_deleted.to_string(), b.files_deleted.to_string()),
        (
            "Network domains",
            a.network_domains.len().to_string(),
            b.network_domains.len().to_string(),
        ),
        ("Network bytes", fmt_bytes(a.network_bytes), fmt_bytes(b.network_bytes)),
        ("Processes", a.processes_spawned.to_string(), b.processes_spawned.to_string()),
        ("Blocked ops", a.blocked_operations.to_string(), b.blocked_operations.to_string()),
        ("Total events", a.total_events.to_string(), b.total_events.to_string()),
    ];

    for (label, va, vb) in &rows {
        println!(
            "│{:<w_label$}│{:<w_col$}│{:<w_col$}│",
            format!(" {label}"),
            format!(" {va}"),
            format!(" {vb}"),
        );
    }

    // Unique-to sections
    let domains_a: Vec<&str> = a.network_domains.iter().map(|(d, _)| d.as_str()).collect();
    let domains_b: Vec<&str> = b.network_domains.iter().map(|(d, _)| d.as_str()).collect();
    let unique_a: Vec<&&str> = domains_a.iter().filter(|d| !domains_b.contains(d)).collect();
    let unique_b: Vec<&&str> = domains_b.iter().filter(|d| !domains_a.contains(d)).collect();

    if !unique_a.is_empty() || !unique_b.is_empty() {
        println!("├{:─<w_label$}┼{:─<w_col$}┴{:─<w_col$}┤", "", "", "");

        if !unique_a.is_empty() {
            let joined = unique_a.iter().map(|d| **d).collect::<Vec<_>>().join(", ");
            println!(
                "│{:<w_label$}│ {:<rest$}│",
                " Unique to A",
                joined,
                rest = w_col * 2 + 1
            );
        }
        if !unique_b.is_empty() {
            let joined = unique_b.iter().map(|d| **d).collect::<Vec<_>>().join(", ");
            println!(
                "│{:<w_label$}│ {:<rest$}│",
                " Unique to B",
                joined,
                rest = w_col * 2 + 1
            );
        }
        println!("└{:─<w_label$}┴{:─<rest$}┘", "", "", rest = w_col * 2 + 1);
    } else {
        println!("└{:─<w_label$}┴{:─<w_col$}┴{:─<w_col$}┘", "", "", "");
    }

    println!();
}

trait PadEnd {
    fn pad_end(&self, width: usize, ch: char) -> String;
}

impl PadEnd for str {
    fn pad_end(&self, width: usize, ch: char) -> String {
        let mut s = self.to_string();
        while s.chars().count() < width { s.push(ch); }
        s
    }
}
