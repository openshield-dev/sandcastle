//! Snapshot branching — create parallel lines of sandbox state.

use crate::{error::SnapshotError, snapshot::SnapshotMetadata, store::SnapshotStore};

/// Manages snapshot branches (parallel sandbox states derived from a common
/// ancestor).
pub struct BranchManager<'a> {
    store: &'a mut SnapshotStore,
}

impl<'a> BranchManager<'a> {
    /// Wrap a mutable reference to a [`SnapshotStore`].
    pub fn new(store: &'a mut SnapshotStore) -> Self {
        Self { store }
    }

    /// Create a new snapshot branching from `source_name`.
    ///
    /// The new snapshot is a full copy of the source with `branch_name` as
    /// its name and branch label, and the source's UUID recorded as its
    /// parent.
    pub fn create_branch(
        &mut self,
        source_name: &str,
        branch_name: &str,
    ) -> Result<SnapshotMetadata, SnapshotError> {
        // Resolve source — keep only what we need to avoid borrow conflicts.
        let (source_id, source_data_path) = {
            let meta = self.store.get(source_name)?;
            (meta.id, self.store_root().join(meta.id.to_string()))
        };

        if !source_data_path.exists() {
            return Err(SnapshotError::Corrupted(format!(
                "source snapshot '{}' data directory is missing",
                source_name
            )));
        }

        self.store.create_with_parent(
            branch_name,
            &source_data_path,
            Some(format!("Branch of '{}'", source_name)),
            Some(source_id),
            Some(branch_name.to_owned()),
        )
    }

    /// Return metadata for every snapshot that was directly branched from
    /// `source_name` (i.e. whose `parent` ID matches that of `source_name`).
    pub fn list_branches(
        &self,
        source_name: &str,
    ) -> Result<Vec<&SnapshotMetadata>, SnapshotError> {
        let source_id = self.store.get(source_name)?.id;
        let mut branches: Vec<&SnapshotMetadata> = self
            .store
            .list()
            .into_iter()
            .filter(|m| m.parent == Some(source_id))
            .collect();
        branches.sort_by_key(|m| m.created_at);
        Ok(branches)
    }

    /// Return the full ancestor chain for `name`, from the root snapshot to
    /// the named snapshot (inclusive), oldest first.
    pub fn history(&self, name: &str) -> Result<Vec<&SnapshotMetadata>, SnapshotError> {
        let mut chain = Vec::new();
        let mut current = self.store.get(name)?;
        chain.push(current);

        while let Some(parent_id) = current.parent {
            match self.store.get_by_id(parent_id) {
                Some(parent) => {
                    chain.push(parent);
                    current = parent;
                }
                None => break, // parent was deleted; stop the walk
            }
        }

        chain.reverse();
        Ok(chain)
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Return the store root path (needed to build data directory paths
    /// without borrowing through the store's private field).
    fn store_root(&self) -> &std::path::Path {
        // SnapshotStore exposes store_root as a field via the pub(crate) accessor.
        self.store.store_root()
    }
}
