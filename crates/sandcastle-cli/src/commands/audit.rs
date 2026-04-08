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
    let log_path = match file {
        Some(f) => std::path::PathBuf::from(f),
        None => std::env::current_dir()
            .context("Failed to determine current directory")?
            .join(".sandcastle/audit.log"),
    };

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
    let non_empty_lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    let total_lines = non_empty_lines.len();

    let mut events: Vec<AuditEvent> = Vec::new();
    let mut parse_failures: usize = 0;
    for line in &non_empty_lines {
        match serde_json::from_str::<AuditEvent>(line) {
            Ok(event) => events.push(event),
            Err(_) => parse_failures += 1,
        }
    }

    if parse_failures > 0 {
        eprintln!(
            "Warning: {parse_failures} of {total_lines} lines could not be parsed"
        );
    }

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
