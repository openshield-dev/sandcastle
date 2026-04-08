//! Core snapshot types — metadata and on-disk representation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Metadata for a single snapshot, persisted in the store index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Parent snapshot ID (set when this snapshot was created as a branch).
    pub parent: Option<Uuid>,
    /// Branch label, if this snapshot belongs to a named branch.
    pub branch: Option<String>,
    pub size_bytes: u64,
    pub file_count: u64,
    pub tags: Vec<String>,
}

/// A point-in-time snapshot of a sandbox state, combining metadata with its
/// on-disk data directory.
#[derive(Debug)]
pub struct Snapshot {
    pub metadata: SnapshotMetadata,
    /// Absolute path to the directory holding this snapshot's file tree.
    pub data_path: PathBuf,
}

impl Snapshot {
    /// Create a new snapshot record.  `size_bytes` and `file_count` are left
    /// at 0 — call [`Snapshot::calculate_size`] and [`Snapshot::count_files`]
    /// after the data directory has been populated.
    pub fn new(name: String, data_path: PathBuf, parent: Option<Uuid>) -> Self {
        Self {
            metadata: SnapshotMetadata {
                id: Uuid::new_v4(),
                name,
                description: None,
                created_at: Utc::now(),
                parent,
                branch: None,
                size_bytes: 0,
                file_count: 0,
                tags: Vec::new(),
            },
            data_path,
        }
    }

    /// Walk the snapshot's data directory and sum file sizes.
    pub fn calculate_size(&self) -> Result<u64, std::io::Error> {
        total_size(&self.data_path)
    }

    /// Walk the snapshot's data directory and count regular files.
    pub fn count_files(&self) -> Result<u64, std::io::Error> {
        count_files_in(&self.data_path)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Recursively sum the sizes of all regular files under `dir`.
pub(crate) fn total_size(dir: &std::path::Path) -> Result<u64, std::io::Error> {
    let mut total = 0u64;
    if !dir.exists() {
        return Ok(0);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_dir() {
            total = total.checked_add(total_size(&entry.path())?).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "snapshot size overflow")
            })?;
        } else {
            total = total.checked_add(meta.len()).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "snapshot size overflow")
            })?;
        }
    }
    Ok(total)
}

/// Recursively count regular files under `dir`.
pub(crate) fn count_files_in(dir: &std::path::Path) -> Result<u64, std::io::Error> {
    let mut count = 0u64;
    if !dir.exists() {
        return Ok(0);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_dir() {
            count = count.checked_add(count_files_in(&entry.path())?).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "snapshot file count overflow")
            })?;
        } else {
            count = count.checked_add(1).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "snapshot file count overflow")
            })?;
        }
    }
    Ok(count)
}
