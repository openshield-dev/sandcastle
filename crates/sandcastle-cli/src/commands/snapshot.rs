//! Implementation of the `sandcastle snapshot` subcommands.

use anyhow::Context;
use sandcastle_snapshot::{BranchManager, SnapshotDiff, SnapshotStore};
use super::validate::validate_name;

/// Default location of the snapshot store relative to the current directory.
const STORE_DIR: &str = ".sandcastle/snapshots";

/// Open (or create) the snapshot store in the current working directory.
fn open_store() -> anyhow::Result<SnapshotStore> {
    let store_path = std::env::current_dir()
        .context("Failed to determine current directory")?
        .join(STORE_DIR);
    SnapshotStore::open(store_path).context("Failed to open snapshot store")
}

/// Create a new snapshot of the current working directory.
pub fn create(name: &str, description: Option<&str>) -> anyhow::Result<()> {
    validate_name(name)?;
    let mut store = open_store()?;
    let source = std::env::current_dir().context("Failed to determine current directory")?;

    let meta = store
        .create(name, &source, description.map(str::to_owned))
        .with_context(|| format!("Failed to create snapshot '{name}'"))?;

    println!(
        "snapshot '{}' created  id={}  files={}  size={}B",
        meta.name, meta.id, meta.file_count, meta.size_bytes
    );
    if let Some(desc) = &meta.description {
        println!("  description: {desc}");
    }
    Ok(())
}

/// List all snapshots in the store.
pub fn list() -> anyhow::Result<()> {
    let store = open_store()?;
    let snapshots = store.list();

    if snapshots.is_empty() {
        println!("No snapshots found. Run `sandcastle snapshot create <name>` to create one.");
        return Ok(());
    }

    println!("{:<30} {:<38} {:>8} {:>10}", "NAME", "ID", "FILES", "SIZE");
    println!("{}", "-".repeat(90));
    for meta in snapshots {
        println!(
            "{:<30} {:<38} {:>8} {:>10}",
            meta.name,
            meta.id,
            meta.file_count,
            format_bytes(meta.size_bytes),
        );
        if let Some(desc) = &meta.description {
            println!("  {desc}");
        }
        if let Some(branch) = &meta.branch {
            println!("  branch: {branch}");
        }
    }
    Ok(())
}

/// Show the diff between a snapshot and the current working directory.
pub fn diff(name: &str) -> anyhow::Result<()> {
    validate_name(name)?;
    let store = open_store()?;
    let meta = store
        .get(name)
        .with_context(|| format!("Snapshot '{name}' not found"))?;

    let store_root = std::env::current_dir()
        .context("Failed to determine current directory")?
        .join(STORE_DIR);
    let snapshot_data = store_root.join(meta.id.to_string());
    let current = std::env::current_dir().context("Failed to determine current directory")?;

    let diff = SnapshotDiff::compare_with_current(&snapshot_data, &current)
        .context("Failed to compute diff")?;

    println!("Diff since snapshot '{}' (id={}):", meta.name, meta.id);
    println!("  {}", diff.summary());

    if diff.entries.is_empty() {
        println!("  No changes.");
        return Ok(());
    }

    println!();
    for entry in &diff.entries {
        let marker = match entry.diff_type {
            sandcastle_snapshot::DiffType::Added => "+",
            sandcastle_snapshot::DiffType::Modified => "~",
            sandcastle_snapshot::DiffType::Deleted => "-",
        };
        println!("  {} {}", marker, entry.path.display());
    }
    Ok(())
}

/// Restore a snapshot to the current working directory.
pub fn restore(name: &str) -> anyhow::Result<()> {
    validate_name(name)?;
    let store = open_store()?;
    let target = std::env::current_dir().context("Failed to determine current directory")?;

    store
        .restore(name, &target)
        .with_context(|| format!("Failed to restore snapshot '{name}'"))?;

    println!("Snapshot '{name}' restored to {}", target.display());
    Ok(())
}

/// Create a branch from an existing snapshot.
pub fn branch(source: &str, name: &str) -> anyhow::Result<()> {
    validate_name(source)?;
    validate_name(name)?;
    let mut store = open_store()?;
    let mut mgr = BranchManager::new(&mut store);

    let meta = mgr
        .create_branch(source, name)
        .with_context(|| format!("Failed to branch '{}' → '{}'", source, name))?;

    println!(
        "Branch '{}' created from '{}' (id={})",
        meta.name, source, meta.id
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1}GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1}MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1_024 {
        format!("{:.1}KB", bytes as f64 / 1_024.0)
    } else {
        format!("{bytes}B")
    }
}
