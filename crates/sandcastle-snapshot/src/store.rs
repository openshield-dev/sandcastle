//! Snapshot store — persists and retrieves snapshots on disk.

use crate::error::SnapshotError;
use crate::manifest::SnapshotManifest;
use std::path::PathBuf;

/// Manages snapshot archives on disk under a root directory.
#[derive(Debug)]
pub struct SnapshotStore {
    root: PathBuf,
}

impl SnapshotStore {
    /// Open (or create) a snapshot store at the given path.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, SnapshotError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// List all manifests in the store.
    pub fn list(&self) -> Result<Vec<SnapshotManifest>, SnapshotError> {
        // Stub: full directory scan will be added in a later milestone.
        Ok(vec![])
    }
}
