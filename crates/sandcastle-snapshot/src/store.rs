//! Snapshot store — persists and retrieves snapshots on disk.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::error::SnapshotError;
use crate::snapshot::{
    count_files_in, total_size, Snapshot, SnapshotMetadata,
};

/// Name of the JSON file that indexes all snapshots in the store.
const INDEX_FILE: &str = "index.json";

/// Type alias to reduce return type complexity in load_index.
type SnapshotIndex = (HashMap<Uuid, SnapshotMetadata>, HashMap<String, Uuid>);

/// Manages snapshot storage and retrieval under a root directory.
///
/// Each snapshot is stored as a subdirectory named by its UUID containing a
/// verbatim copy of the captured file tree.  An `index.json` at the store
/// root maps UUIDs to [`SnapshotMetadata`] for fast lookups without walking
/// every snapshot directory.
#[derive(Debug)]
pub struct SnapshotStore {
    /// Root directory for all snapshots.
    store_root: PathBuf,
    /// Primary index — UUID → metadata.
    index: HashMap<Uuid, SnapshotMetadata>,
    /// Secondary index — human-readable name → UUID.
    name_index: HashMap<String, Uuid>,
}

impl SnapshotStore {
    /// Open or create a snapshot store at `store_root`.
    pub fn open(store_root: PathBuf) -> Result<Self, SnapshotError> {
        std::fs::create_dir_all(&store_root)?;
        let (index, name_index) = Self::load_index(&store_root)?;
        Ok(Self {
            store_root,
            index,
            name_index,
        })
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Create a new snapshot by copying `source_dir` into the store.
    ///
    /// Returns the metadata for the newly-created snapshot.
    pub fn create(
        &mut self,
        name: &str,
        source_dir: &Path,
        description: Option<String>,
    ) -> Result<SnapshotMetadata, SnapshotError> {
        self.create_with_parent(name, source_dir, description, None, None)
    }

    /// Internal helper used by both [`create`] and [`BranchManager`].
    pub(crate) fn create_with_parent(
        &mut self,
        name: &str,
        source_dir: &Path,
        description: Option<String>,
        parent: Option<Uuid>,
        branch: Option<String>,
    ) -> Result<SnapshotMetadata, SnapshotError> {
        validate_name(name)?;

        if self.name_index.contains_key(name) {
            return Err(SnapshotError::AlreadyExists(name.to_owned()));
        }

        let mut snapshot = Snapshot::new(name.to_owned(), PathBuf::new(), parent);
        snapshot.metadata.description = description;
        snapshot.metadata.branch = branch;

        let data_path = self.store_root.join(snapshot.metadata.id.to_string());
        snapshot.data_path = data_path.clone();

        // Copy the source tree and compute stats, cleaning up on failure.
        let result = (|| -> Result<(), SnapshotError> {
            // Copy the source tree into the snapshot directory.
            copy_dir_all(source_dir, &data_path).map_err(|e| {
                SnapshotError::StorageError(format!(
                    "failed to copy '{}' to snapshot dir: {e}",
                    source_dir.display()
                ))
            })?;

            // Compute stats after the copy.
            snapshot.metadata.size_bytes = total_size(&data_path).map_err(|e| {
                SnapshotError::StorageError(format!(
                    "failed to compute snapshot size: {e}"
                ))
            })?;
            snapshot.metadata.file_count = count_files_in(&data_path).map_err(|e| {
                SnapshotError::StorageError(format!(
                    "failed to count snapshot files: {e}"
                ))
            })?;

            Ok(())
        })();

        if let Err(e) = result {
            let _ = std::fs::remove_dir_all(&data_path);
            return Err(e);
        }

        info!(
            name = %name,
            id = %snapshot.metadata.id,
            size_bytes = snapshot.metadata.size_bytes,
            file_count = snapshot.metadata.file_count,
            "snapshot created"
        );

        self.index
            .insert(snapshot.metadata.id, snapshot.metadata.clone());
        self.name_index
            .insert(name.to_owned(), snapshot.metadata.id);
        self.save_index()?;

        Ok(snapshot.metadata)
    }

    /// Restore a snapshot to `target_dir`.
    ///
    /// `target_dir` is created if it does not exist; any existing contents
    /// are replaced by the snapshot's file tree.  Uses an atomic swap so
    /// that a failed copy does not leave the target in a partially-deleted
    /// state.
    pub fn restore(&self, name: &str, target_dir: &Path) -> Result<(), SnapshotError> {
        validate_name(name)?;

        let meta = self.get(name)?;
        let data_path = self.store_root.join(meta.id.to_string());

        if !data_path.exists() {
            return Err(SnapshotError::Corrupted(format!(
                "data directory for snapshot '{}' is missing: {}",
                name,
                data_path.display()
            )));
        }

        // Copy into a temporary directory next to the target first so a
        // failure never destroys the existing contents.
        let target_parent = target_dir.parent().unwrap_or(Path::new("."));
        let temp_dir = target_parent.join(format!(
            ".sandcastle-restore-{}",
            Uuid::new_v4()
        ));
        let bak_dir = target_parent.join(format!(
            ".sandcastle-bak-{}",
            Uuid::new_v4()
        ));

        copy_dir_all(&data_path, &temp_dir).map_err(|e| {
            let _ = std::fs::remove_dir_all(&temp_dir);
            SnapshotError::RestoreFailed(format!(
                "failed to copy snapshot data to temp dir: {e}"
            ))
        })?;

        // Swap: move old target to backup, move temp to target.
        if target_dir.exists() {
            std::fs::rename(target_dir, &bak_dir).map_err(|e| {
                let _ = std::fs::remove_dir_all(&temp_dir);
                SnapshotError::RestoreFailed(format!(
                    "failed to move target dir to backup: {e}"
                ))
            })?;
        }

        if let Err(e) = std::fs::rename(&temp_dir, target_dir) {
            // Restore the backup if the rename fails.
            if bak_dir.exists() {
                let _ = std::fs::rename(&bak_dir, target_dir);
            }
            let _ = std::fs::remove_dir_all(&temp_dir);
            return Err(SnapshotError::RestoreFailed(format!(
                "failed to move restored snapshot to target: {e}"
            )));
        }

        // Clean up the backup directory.
        if bak_dir.exists() {
            let _ = std::fs::remove_dir_all(&bak_dir);
        }

        info!(name = %name, target = %target_dir.display(), "snapshot restored");
        Ok(())
    }

    /// Return metadata for every snapshot in the store, ordered by creation
    /// time (oldest first).
    pub fn list(&self) -> Vec<&SnapshotMetadata> {
        let mut items: Vec<&SnapshotMetadata> = self.index.values().collect();
        items.sort_by_key(|m| m.created_at);
        items
    }

    /// Look up a snapshot by name.
    pub fn get(&self, name: &str) -> Result<&SnapshotMetadata, SnapshotError> {
        let id = self
            .name_index
            .get(name)
            .ok_or_else(|| SnapshotError::NotFound(name.to_owned()))?;
        self.index
            .get(id)
            .ok_or_else(|| SnapshotError::NotFound(name.to_owned()))
    }

    /// Look up a snapshot by UUID (used internally by the branch manager).
    pub(crate) fn get_by_id(&self, id: Uuid) -> Option<&SnapshotMetadata> {
        self.index.get(&id)
    }

    /// Return the store root path (used by the branch manager to build data
    /// directory paths without needing direct field access).
    pub(crate) fn store_root(&self) -> &Path {
        &self.store_root
    }

    /// Delete a snapshot from the store, removing its data directory.
    pub fn delete(&mut self, name: &str) -> Result<(), SnapshotError> {
        validate_name(name)?;

        let id = self
            .name_index
            .remove(name)
            .ok_or_else(|| SnapshotError::NotFound(name.to_owned()))?;

        self.index.remove(&id);

        let data_path = self.store_root.join(id.to_string());
        if data_path.exists() {
            std::fs::remove_dir_all(&data_path)?;
        }

        self.save_index()?;
        debug!(name = %name, %id, "snapshot deleted");
        Ok(())
    }

    // ------------------------------------------------------------------
    // Index persistence
    // ------------------------------------------------------------------

    /// Persist the in-memory index to `index.json`.
    fn save_index(&self) -> Result<(), SnapshotError> {
        let path = self.store_root.join(INDEX_FILE);
        let records: Vec<&SnapshotMetadata> = self.index.values().collect();
        let json = serde_json::to_string_pretty(&records)?;
        std::fs::write(&path, json)?;
        Ok(())
    }

    /// Load (or initialise) the index from `index.json` in `store_root`.
    fn load_index(
        store_root: &Path,
    ) -> Result<SnapshotIndex, SnapshotError> {
        let path = store_root.join(INDEX_FILE);

        if !path.exists() {
            return Ok((HashMap::new(), HashMap::new()));
        }

        let raw = std::fs::read_to_string(&path)?;
        let records: Vec<SnapshotMetadata> = serde_json::from_str(&raw).map_err(|e| {
            SnapshotError::Corrupted(format!("index.json is invalid: {e}"))
        })?;

        let mut index = HashMap::with_capacity(records.len());
        let mut name_index = HashMap::with_capacity(records.len());
        for meta in records {
            name_index.insert(meta.name.clone(), meta.id);
            index.insert(meta.id, meta);
        }

        Ok((index, name_index))
    }
}

// ---------------------------------------------------------------------------
// Internal filesystem helpers
// ---------------------------------------------------------------------------

/// Validate a snapshot name, rejecting path traversal, empty names, and
/// non-portable characters.
fn validate_name(name: &str) -> Result<(), SnapshotError> {
    if name.is_empty() {
        return Err(SnapshotError::InvalidName(
            "name must not be empty".to_owned(),
        ));
    }
    if name.len() > 255 {
        return Err(SnapshotError::InvalidName(
            "name must not exceed 255 characters".to_owned(),
        ));
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") || name.contains('\0') {
        return Err(SnapshotError::InvalidName(
            "name must not contain '/', '\\', '..', or null bytes".to_owned(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(SnapshotError::InvalidName(
            "name may only contain alphanumeric characters, hyphens, underscores, and dots"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn validate_name_rejects_path_traversal() {
        let result = validate_name("../escape");
        assert!(result.is_err(), "names containing '..' must be rejected");
    }

    #[test]
    fn validate_name_rejects_slashes() {
        assert!(validate_name("dir/name").is_err(), "forward slash must be rejected");
        assert!(validate_name("dir\\name").is_err(), "backslash must be rejected");
    }

    #[test]
    fn validate_name_rejects_empty() {
        assert!(validate_name("").is_err(), "empty name must be rejected");
    }

    #[test]
    fn validate_name_accepts_valid() {
        assert!(validate_name("my-snapshot_v1.0").is_ok(), "valid name with hyphens, underscores, and dots must be accepted");
    }

    #[test]
    fn create_and_list_snapshot() {
        // Set up a temporary store root and a source directory with a file.
        let store_tmp = tempfile::tempdir().unwrap();
        let source_tmp = tempfile::tempdir().unwrap();
        fs::write(source_tmp.path().join("hello.txt"), b"world").unwrap();

        let mut store = SnapshotStore::open(store_tmp.path().to_path_buf()).unwrap();

        // Create a snapshot.
        let meta = store.create("test-snap", source_tmp.path(), Some("test description".into())).unwrap();
        assert_eq!(meta.name, "test-snap");
        assert_eq!(meta.file_count, 1);

        // List snapshots — should contain exactly one.
        let list = store.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "test-snap");
    }
}

/// Recursively copy the entire directory tree from `src` into `dst`.
///
/// `dst` and any intermediate directories are created automatically.
/// Symlinks are skipped to prevent path-traversal attacks.
fn copy_dir_all(src: &Path, dst: &Path) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&src_path)?;

        if meta.file_type().is_symlink() {
            warn!("Skipping symlink: {}", src_path.display());
            continue;
        }

        if meta.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}
