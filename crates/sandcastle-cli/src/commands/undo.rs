//! Implementation of the `sandcastle undo` command — one-command rollback of the
//! last sandbox run by restoring the auto-snapshot taken before the run.

use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use anyhow::Context;
use chrono::Utc;
use sandcastle_snapshot::{SnapshotDiff, SnapshotStore};

/// Prefix used for auto-snapshots created before each sandbox run.
const AUTO_SNAPSHOT_PREFIX: &str = "auto-pre-run-";

/// Default location of the snapshot store relative to the current directory.
const STORE_DIR: &str = ".sandcastle/snapshots";

/// Default location of the audit log relative to the current directory.
const AUDIT_LOG: &str = ".sandcastle/audit.log";

/// Open (or create) the snapshot store in the current working directory.
fn open_store() -> anyhow::Result<SnapshotStore> {
    let store_path = std::env::current_dir()
        .context("Failed to determine current directory")?
        .join(STORE_DIR);
    SnapshotStore::open(store_path).context("Failed to open snapshot store")
}

/// Create an auto-snapshot named `auto-pre-run-{ISO timestamp}`.
///
/// This is intended to be called from `run.rs` before launching a sandboxed
/// process so that `sandcastle undo` can restore the pre-run state.
///
/// Returns the snapshot name on success.
pub fn create_auto_snapshot() -> anyhow::Result<String> {
    let mut store = open_store()?;
    let source = std::env::current_dir().context("Failed to determine current directory")?;

    // Build a filesystem-safe timestamp: replace colons with dashes.
    let timestamp = Utc::now().format("%Y-%m-%dT%H-%M-%S").to_string();
    let name = format!("{AUTO_SNAPSHOT_PREFIX}{timestamp}");

    store
        .create(&name, &source, Some("auto-snapshot before sandbox run".into()))
        .with_context(|| format!("Failed to create auto-snapshot '{name}'"))?;

    Ok(name)
}

/// Execute the `sandcastle undo` command.
///
/// When `confirm` is `true` (the `--yes` flag), the restore proceeds without
/// prompting.  Otherwise the user is shown what would be undone and asked to
/// confirm.
pub fn execute(confirm: bool) -> anyhow::Result<()> {
    let store = open_store()?;

    // 1. Find the most recent auto-snapshot.
    let snapshots = store.list(); // sorted oldest-first
    let latest = snapshots
        .iter()
        .rev()
        .find(|m| m.name.starts_with(AUTO_SNAPSHOT_PREFIX))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "No auto-snapshots found in {STORE_DIR}. \
                 Run a sandboxed command first so an auto-snapshot is created."
            )
        })?;

    // 2. Compute diff between the snapshot and the current working directory.
    let cwd = std::env::current_dir().context("Failed to determine current directory")?;
    let store_path = cwd.join(STORE_DIR);
    let snapshot_data = store_path.join(latest.id.to_string());

    let diff = SnapshotDiff::compare_with_current(&snapshot_data, &cwd)
        .context("Failed to compute diff against snapshot")?;

    // 3. Augment with audit log event count if available.
    let audit_event_count = count_audit_events(&cwd.join(AUDIT_LOG));

    // 4. If not auto-confirmed, show preview and prompt.
    if !confirm {
        println!(
            "sandcastle undo: will restore to pre-run snapshot '{}'",
            latest.name
        );
        println!();
        println!("Changes since snapshot:");
        println!("  {} files modified", diff.total_modified);
        println!("  {} files created", diff.total_added);
        println!("  {} files deleted", diff.total_deleted);
        if let Some(count) = audit_event_count {
            println!("  {count} audit events recorded");
        }
        println!();
        print!("Proceed? [y/N] ");
        io::stdout().flush().context("Failed to flush stdout")?;

        let mut answer = String::new();
        io::stdin()
            .lock()
            .read_line(&mut answer)
            .context("Failed to read user input")?;

        if !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
            println!("sandcastle: undo cancelled");
            return Ok(());
        }
    }

    // 5. Restore the snapshot.
    store
        .restore(&latest.name, &cwd)
        .with_context(|| format!("Failed to restore snapshot '{}'", latest.name))?;

    // 6. Print success summary.
    let mut parts: Vec<String> = Vec::new();
    if diff.total_modified > 0 {
        parts.push(format!("{} files reverted", diff.total_modified));
    }
    if diff.total_added > 0 {
        parts.push(format!("{} files removed", diff.total_added));
    }
    if diff.total_deleted > 0 {
        parts.push(format!("{} files undeleted", diff.total_deleted));
    }

    let detail = if parts.is_empty() {
        "no file changes".to_string()
    } else {
        parts.join(", ")
    };

    println!("sandcastle: restored to pre-run state ({detail})");
    Ok(())
}

/// Count the number of lines (events) in the audit log file. Returns `None` if
/// the file does not exist or cannot be read.
fn count_audit_events(audit_path: &PathBuf) -> Option<u64> {
    let content = std::fs::read_to_string(audit_path).ok()?;
    let count = content.lines().filter(|l| !l.trim().is_empty()).count() as u64;
    if count > 0 { Some(count) } else { None }
}
