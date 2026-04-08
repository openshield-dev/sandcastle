//! Implementation of the `sandcastle diff` command.
//!
//! Shows what an agent changed during its last run by analyzing the audit log
//! and optional snapshot state.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Context;
use sandcastle_audit::event::{AuditEvent, EventType, PolicyDecision};
use sandcastle_audit::store::AuditStore;

/// Default path to the audit log file relative to the working directory.
const DEFAULT_AUDIT_LOG: &str = ".sandcastle/audit.log";

/// A network endpoint aggregated across multiple events.
struct NetEntry {
    domain: String,
    requests: u64,
    bytes: u64,
    blocked: bool,
}

/// A process command aggregated across multiple events.
struct ProcEntry {
    command: String,
    count: u64,
    allowed: bool,
}

/// A blocked operation extracted from a denied event.
struct BlockedOp {
    kind: &'static str,
    target: String,
}

/// Execute the `sandcastle diff` command.
///
/// Reads the audit log, groups events by session, and prints a formatted
/// summary of the latest session's activity. If `snapshot_name` is provided,
/// also shows the filesystem diff from that snapshot.
pub fn execute(audit_file: Option<&str>, snapshot_name: Option<&str>) -> anyhow::Result<()> {
    let log_path = audit_file.unwrap_or(DEFAULT_AUDIT_LOG);
    let path = Path::new(log_path);

    if !path.exists() {
        anyhow::bail!(
            "Audit log not found at '{}'. Run a sandboxed command first.",
            log_path
        );
    }

    let events = AuditStore::read_all(path)
        .with_context(|| format!("Failed to read audit log at '{}'", log_path))?;

    if events.is_empty() {
        println!("No events found in audit log.");
        return Ok(());
    }

    // Group events by session_id and pick the latest session.
    let session_events = latest_session_events(&events);

    print_summary(&session_events);

    // If a snapshot name is provided, show filesystem diff from that snapshot.
    if let Some(name) = snapshot_name {
        print_snapshot_diff(name)?;
    }

    Ok(())
}

/// Extract events belonging to the most recent session (by timestamp).
fn latest_session_events(events: &[AuditEvent]) -> Vec<&AuditEvent> {
    let mut by_session: HashMap<uuid::Uuid, Vec<&AuditEvent>> = HashMap::new();
    for event in events {
        by_session.entry(event.session_id).or_default().push(event);
    }

    // Find the session whose last event has the latest timestamp.
    by_session
        .into_values()
        .max_by_key(|evts| evts.iter().map(|e| e.timestamp).max())
        .unwrap_or_default()
}

/// Print the formatted run summary for a set of session events.
fn print_summary(events: &[&AuditEvent]) {
    if events.is_empty() {
        println!("No events in session.");
        return;
    }

    let first = events.first().unwrap();
    let session_id = &first.session_id.to_string()[..8];
    let profile = first
        .context
        .profile
        .as_deref()
        .unwrap_or("unknown");
    let trust = first
        .context
        .trust_level
        .as_deref()
        .unwrap_or("unknown");

    let total = events.len();
    let blocked_count = events.iter().filter(|e| e.is_violation()).count();

    // Compute duration from first to last event.
    let ts_min = events.iter().map(|e| e.timestamp).min().unwrap();
    let ts_max = events.iter().map(|e| e.timestamp).max().unwrap();
    let duration = ts_max.signed_duration_since(ts_min);
    let dur_secs = duration.num_seconds();
    let dur_str = if dur_secs >= 60 {
        format!("{}m {}s", dur_secs / 60, dur_secs % 60)
    } else {
        format!("{}s", dur_secs)
    };

    // Header
    println!();
    println!("--- SandCastle Run Summary -------------------------------------------");
    println!(
        "Session: {}  Profile: {}  Trust: {}",
        session_id, profile, trust
    );
    println!(
        "Duration: {}  Events: {}  Blocked: {}",
        dur_str, total, blocked_count
    );

    // Categorize filesystem events.
    let mut files_read: Vec<&str> = Vec::new();
    let mut files_written: Vec<&str> = Vec::new();
    let mut files_created: Vec<&str> = Vec::new();
    let mut files_deleted: Vec<&str> = Vec::new();
    let mut net_map: HashMap<String, NetEntry> = HashMap::new();
    let mut proc_map: HashMap<String, ProcEntry> = HashMap::new();
    let mut blocked_ops: Vec<BlockedOp> = Vec::new();

    for event in events {
        let is_allowed = event.policy_result.decision == PolicyDecision::Allow;
        match &event.event_type {
            EventType::FilesystemRead => {
                if let Some(p) = event.action.path.as_deref() {
                    if !is_allowed {
                        blocked_ops.push(BlockedOp { kind: "READ", target: p.to_owned() });
                    } else {
                        files_read.push(p);
                    }
                }
            }
            EventType::FilesystemWrite => {
                if let Some(p) = event.action.path.as_deref() {
                    if !is_allowed {
                        blocked_ops.push(BlockedOp { kind: "WRITE", target: p.to_owned() });
                    } else {
                        files_written.push(p);
                    }
                }
            }
            EventType::FilesystemCreate => {
                if let Some(p) = event.action.path.as_deref() {
                    if !is_allowed {
                        blocked_ops.push(BlockedOp { kind: "CREATE", target: p.to_owned() });
                    } else {
                        files_created.push(p);
                    }
                }
            }
            EventType::FilesystemDelete => {
                if let Some(p) = event.action.path.as_deref() {
                    if !is_allowed {
                        blocked_ops.push(BlockedOp { kind: "DELETE", target: p.to_owned() });
                    } else {
                        files_deleted.push(p);
                    }
                }
            }
            EventType::NetworkConnect | EventType::NetworkRequest => {
                let domain = event
                    .action
                    .domain
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_owned();
                let entry = net_map.entry(domain.clone()).or_insert(NetEntry {
                    domain,
                    requests: 0,
                    bytes: 0,
                    blocked: !is_allowed,
                });
                entry.requests += 1;
                entry.bytes += event.action.size_bytes.unwrap_or(0);
                if !is_allowed {
                    entry.blocked = true;
                    blocked_ops.push(BlockedOp { kind: "NET", target: entry.domain.clone() });
                }
            }
            EventType::ProcessExec | EventType::ProcessSpawn => {
                let cmd = event
                    .action
                    .command
                    .as_deref()
                    .unwrap_or("unknown")
                    .to_owned();
                let entry = proc_map.entry(cmd.clone()).or_insert(ProcEntry {
                    command: cmd,
                    count: 0,
                    allowed: is_allowed,
                });
                entry.count += 1;
                if !is_allowed {
                    entry.allowed = false;
                }
            }
            _ => {}
        }
    }

    // Modified Files section
    let has_file_changes = !files_written.is_empty()
        || !files_created.is_empty()
        || !files_deleted.is_empty();
    if has_file_changes {
        println!();
        println!("Modified Files:");
        for p in &files_written {
            println!("  M {}", p);
        }
        for p in &files_created {
            println!("  A {}", p);
        }
        for p in &files_deleted {
            println!("  D {}", p);
        }
    }

    // Network Activity section
    if !net_map.is_empty() {
        println!();
        println!("Network Activity:");
        let mut entries: Vec<&NetEntry> = net_map.values().collect();
        entries.sort_by(|a, b| b.requests.cmp(&a.requests));
        for entry in entries {
            if entry.blocked {
                println!(
                    "  x {}  BLOCKED ({} attempt{})",
                    entry.domain,
                    entry.requests,
                    if entry.requests == 1 { "" } else { "s" }
                );
            } else {
                let size_str = format_bytes(entry.bytes);
                println!(
                    "  + {}  {} request{}, {}",
                    entry.domain,
                    entry.requests,
                    if entry.requests == 1 { "" } else { "s" },
                    size_str
                );
            }
        }
    }

    // Processes section
    if !proc_map.is_empty() {
        println!();
        println!("Processes:");
        let mut entries: Vec<&ProcEntry> = proc_map.values().collect();
        entries.sort_by(|a, b| b.count.cmp(&a.count));
        for entry in entries {
            let marker = if entry.allowed { "+" } else { "x" };
            println!(
                "  {} {}  ({} time{})",
                marker,
                entry.command,
                entry.count,
                if entry.count == 1 { "" } else { "s" }
            );
        }
    }

    // Blocked Operations section — deduplicate
    if !blocked_ops.is_empty() {
        let mut seen: HashMap<String, ()> = HashMap::new();
        println!();
        println!("Blocked Operations:");
        for op in &blocked_ops {
            let key = format!("{} {}", op.kind, op.target);
            if seen.contains_key(&key) {
                continue;
            }
            seen.insert(key, ());
            println!("  x {:6} {}", op.kind, op.target);
        }
    }

    println!();
}

/// Format byte count into a human-readable string.
fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1}MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{}KB", bytes / 1024)
    } else {
        format!("{}B", bytes)
    }
}

/// Print a filesystem diff from a named snapshot against the current directory.
fn print_snapshot_diff(snapshot_name: &str) -> anyhow::Result<()> {
    let store_path = std::env::current_dir()
        .context("Failed to determine current directory")?
        .join(".sandcastle")
        .join("snapshots");

    let store = sandcastle_snapshot::SnapshotStore::open(store_path)
        .context("Failed to open snapshot store")?;

    let meta = store
        .get(snapshot_name)
        .with_context(|| format!("Snapshot '{}' not found", snapshot_name))?;

    let snapshot_dir = std::env::current_dir()
        .context("Failed to determine current directory")?
        .join(".sandcastle")
        .join("snapshots")
        .join(meta.id.to_string());

    let current_dir = std::env::current_dir().context("Failed to determine current directory")?;

    let diff = sandcastle_snapshot::SnapshotDiff::compare_with_current(&snapshot_dir, &current_dir)
        .context("Failed to compute snapshot diff")?;

    println!("--- Snapshot Diff ({}) ---", snapshot_name);
    println!("{}", diff.summary());

    for entry in &diff.entries {
        let marker = match entry.diff_type {
            sandcastle_snapshot::DiffType::Added => "A",
            sandcastle_snapshot::DiffType::Modified => "M",
            sandcastle_snapshot::DiffType::Deleted => "D",
        };
        let size_info = match entry.diff_type {
            sandcastle_snapshot::DiffType::Added => {
                format!("(new, {} bytes)", entry.new_size.unwrap_or(0))
            }
            sandcastle_snapshot::DiffType::Deleted => "(deleted)".to_owned(),
            sandcastle_snapshot::DiffType::Modified => {
                let old = entry.old_size.unwrap_or(0) as i64;
                let new = entry.new_size.unwrap_or(0) as i64;
                let delta = new - old;
                let sign = if delta >= 0 { "+" } else { "" };
                format!("({}{} bytes)", sign, delta)
            }
        };
        println!("  {} {}  {}", marker, entry.path.display(), size_info);
    }

    println!();
    Ok(())
}
