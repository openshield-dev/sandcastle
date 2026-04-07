//! Snapshot diffing — compare two directory trees to produce a structured diff.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};

use crate::error::SnapshotError;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The kind of change a [`DiffEntry`] represents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiffType {
    Added,
    Modified,
    Deleted,
}

/// A single file-level change between two snapshot states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    /// Path relative to the compared root directories.
    pub path: PathBuf,
    pub diff_type: DiffType,
    /// Size of the file in the "before" (A) directory, if it existed.
    pub old_size: Option<u64>,
    /// Size of the file in the "after" (B) directory, if it exists.
    pub new_size: Option<u64>,
}

/// The result of comparing two directory trees.
#[derive(Debug)]
pub struct SnapshotDiff {
    pub entries: Vec<DiffEntry>,
    pub total_added: u64,
    pub total_modified: u64,
    pub total_deleted: u64,
}

impl SnapshotDiff {
    /// Walk `dir_a` and `dir_b` and produce a structured diff.
    ///
    /// Files are compared by **size + last-modified time** for performance;
    /// no full content hashing is performed.
    pub fn compare(dir_a: &Path, dir_b: &Path) -> Result<Self, SnapshotError> {
        let files_a = walk_dir(dir_a)?;
        let files_b = walk_dir(dir_b)?;

        let mut entries = Vec::new();
        let mut total_added = 0u64;
        let mut total_modified = 0u64;
        let mut total_deleted = 0u64;

        // Files present in A — check whether they are Modified or Deleted in B.
        for (rel, info_a) in &files_a {
            match files_b.get(rel) {
                None => {
                    // Exists in A but not B → deleted.
                    entries.push(DiffEntry {
                        path: rel.clone(),
                        diff_type: DiffType::Deleted,
                        old_size: Some(info_a.size),
                        new_size: None,
                    });
                    total_deleted += 1;
                }
                Some(info_b) => {
                    if files_differ(info_a, info_b) {
                        entries.push(DiffEntry {
                            path: rel.clone(),
                            diff_type: DiffType::Modified,
                            old_size: Some(info_a.size),
                            new_size: Some(info_b.size),
                        });
                        total_modified += 1;
                    }
                    // Identical — no entry.
                }
            }
        }

        // Files present in B but not in A → added.
        for (rel, info_b) in &files_b {
            if !files_a.contains_key(rel) {
                entries.push(DiffEntry {
                    path: rel.clone(),
                    diff_type: DiffType::Added,
                    old_size: None,
                    new_size: Some(info_b.size),
                });
                total_added += 1;
            }
        }

        // Sort for deterministic output.
        entries.sort_by(|a, b| a.path.cmp(&b.path));

        Ok(Self {
            entries,
            total_added,
            total_modified,
            total_deleted,
        })
    }

    /// Convenience wrapper — compares `snapshot_dir` (the "before") against
    /// `current_dir` (the "after").
    pub fn compare_with_current(
        snapshot_dir: &Path,
        current_dir: &Path,
    ) -> Result<Self, SnapshotError> {
        Self::compare(snapshot_dir, current_dir)
    }

    /// Return a human-readable one-line summary of the diff.
    pub fn summary(&self) -> String {
        format!(
            "+{} added  ~{} modified  -{} deleted  ({} total changes)",
            self.total_added,
            self.total_modified,
            self.total_deleted,
            self.entries.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Lightweight file metadata used for quick comparison.
#[derive(Debug)]
struct FileInfo {
    size: u64,
    modified: Option<SystemTime>,
}

/// Walk a directory tree and collect relative path → [`FileInfo`] for every
/// regular file.  Returns an empty map if `dir` does not exist.
fn walk_dir(dir: &Path) -> Result<HashMap<PathBuf, FileInfo>, SnapshotError> {
    let mut map = HashMap::new();
    if !dir.exists() {
        return Ok(map);
    }
    walk_dir_inner(dir, dir, &mut map)?;
    Ok(map)
}

fn walk_dir_inner(
    root: &Path,
    current: &Path,
    map: &mut HashMap<PathBuf, FileInfo>,
) -> Result<(), SnapshotError> {
    for entry in std::fs::read_dir(current)? {
        let entry = entry?;
        let abs = entry.path();
        let meta = entry.metadata()?;

        if meta.is_dir() {
            walk_dir_inner(root, &abs, map)?;
        } else {
            let rel = abs
                .strip_prefix(root)
                .map_err(|e| {
                    SnapshotError::StorageError(format!("strip_prefix failed: {e}"))
                })?
                .to_path_buf();
            map.insert(
                rel,
                FileInfo {
                    size: meta.len(),
                    modified: meta.modified().ok(),
                },
            );
        }
    }
    Ok(())
}

/// Return `true` when the two [`FileInfo`] records represent a changed file.
///
/// Two files are considered identical when their size AND modification
/// timestamp both match.  If either mtime is unavailable we fall back to
/// comparing sizes only.
fn files_differ(a: &FileInfo, b: &FileInfo) -> bool {
    if a.size != b.size {
        return true;
    }
    match (a.modified, b.modified) {
        (Some(ma), Some(mb)) => ma != mb,
        _ => false, // sizes match and we have no mtime — assume identical
    }
}
