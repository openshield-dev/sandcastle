//! Implementation of the `sandcastle audit` command.

use anyhow::Context;
use sandcastle_audit::AuditEvent;

/// Execute the `sandcastle audit` command.
///
/// Reads NDJSON audit events from `file` (or the default log path), applies
/// filters, and prints results in the requested format.
pub fn execute(
    last: Option<usize>,
    violations_only: bool,
    export: Option<&str>,
    file: Option<&str>,
) -> anyhow::Result<()> {
    let log_path = file
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_dir()
                .unwrap_or_default()
                .join(".sandcastle/audit.log")
        });

    if !log_path.exists() {
        println!(
            "No audit log found at {}.",
            log_path.display()
        );
        println!("Start a sandboxed session with `sandcastle run` to generate audit events.");
        return Ok(());
    }

    let raw = std::fs::read_to_string(&log_path)
        .with_context(|| format!("Failed to read audit log '{}'", log_path.display()))?;

    // Parse NDJSON — each line is one JSON-encoded AuditEvent.
    let mut events: Vec<AuditEvent> = raw
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();

    // Apply violations-only filter.
    if violations_only {
        events.retain(|e| e.is_violation());
    }

    // Apply --last N.
    if let Some(n) = last {
        let len = events.len();
        if n < len {
            events = events[len - n..].to_vec();
        }
    }

    if events.is_empty() {
        println!("No audit events match the given filters.");
        return Ok(());
    }

    match export.unwrap_or("text") {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&events)?);
        }
        "csv" => {
            println!("id,timestamp,sandbox_id,event_type,decision,description");
            for e in &events {
                println!(
                    "{},{},{},{},{},\"{}\"",
                    e.id,
                    e.timestamp.to_rfc3339(),
                    e.sandbox_id,
                    e.event_type,
                    e.policy_result.decision,
                    e.action.description.replace('"', "\"\"")
                );
            }
        }
        _ => {
            // Default: human-readable text.
            for e in &events {
                let status = if e.is_allowed() { "ALLOW" } else { "DENY " };
                println!(
                    "[{}] {} {:>20} {} — {}",
                    e.timestamp.format("%Y-%m-%d %H:%M:%SZ"),
                    status,
                    e.event_type.to_string(),
                    e.sandbox_id,
                    e.action.description
                );
            }
        }
    }

    Ok(())
}
