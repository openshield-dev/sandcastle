//! Copy-on-write (CoW) directory semantics.
//!
//! Reads are served from `source` unless the file has already been written,
//! in which case the modified copy in `cow_dir` is returned instead.
//! All writes are directed to `cow_dir`, leaving `source` unchanged until an
//! explicit [`CowDirectory::commit`] call.

use std::{
    collections::HashSet,
    path::{Component, Path, PathBuf},
};
use tracing::debug;

use crate::error::FsError;

/// Reject paths that could escape the sandbox base directory.
///
/// Rejects:
/// - Absolute paths (starting with `/`, `\`, or a Windows drive letter like `C:`)
/// - Paths containing `..` components
/// - Paths containing null bytes
fn validate_relative_path(path: &Path) -> Result<(), FsError> {
    let path_str = path.to_string_lossy();

    // Reject null bytes — these can be used to trick path-handling code.
    if path_str.contains('\0') {
        return Err(FsError::PathTraversal(path.to_path_buf()));
    }

    for component in path.components() {
        match component {
            // Any absolute root, prefix (Windows drive letter), or `..` is rejected.
            Component::RootDir | Component::Prefix(_) | Component::ParentDir => {
                return Err(FsError::PathTraversal(path.to_path_buf()));
            }
            _ => {}
        }
    }

    Ok(())
}

/// Type of change recorded in a [`CowChange`].
#[derive(Debug, Clone)]
pub enum ChangeType {
    Added,
    Modified,
    Deleted,
}

/// A single file-level change produced by [`CowDirectory::diff`].
#[derive(Debug, Clone)]
pub struct CowChange {
    pub path: PathBuf,
    pub change_type: ChangeType,
    pub size_bytes: u64,
}

/// Manages copy-on-write semantics over a directory tree.
#[derive(Debug)]
pub struct CowDirectory {
    /// Original directory (treated as read-only).
    source: PathBuf,
    /// Directory where modified copies are stored.
    cow_dir: PathBuf,
    /// Relative paths that have been written (or deleted) in `cow_dir`.
    copied_paths: HashSet<PathBuf>,
}

impl CowDirectory {
    /// Create a new CoW view.  Both `source` and `cow_dir` must already exist
    /// (or be creatable); `source` is never written to by this type.
    pub fn new(source: PathBuf, cow_dir: PathBuf) -> Result<Self, FsError> {
        std::fs::create_dir_all(&cow_dir).map_err(|e| {
            FsError::CowError(format!(
                "failed to create cow_dir {}: {e}",
                cow_dir.display()
            ))
        })?;

        Ok(CowDirectory {
            source,
            cow_dir,
            copied_paths: HashSet::new(),
        })
    }

    /// Read a file.  Returns the CoW copy if one exists, otherwise falls back
    /// to the original in `source`.
    pub fn read(&self, relative_path: &Path) -> Result<Vec<u8>, FsError> {
        validate_relative_path(relative_path)?;
        let cow_path = self.cow_dir.join(relative_path);
        if cow_path.exists() {
            return std::fs::read(&cow_path).map_err(FsError::Io);
        }

        let src_path = self.source.join(relative_path);
        std::fs::read(&src_path).map_err(FsError::Io)
    }

    /// Write a file.  The original is copied into `cow_dir` first (if it
    /// exists in `source` and hasn't been copied yet), then the new `data`
    /// is written.
    pub fn write(&mut self, relative_path: &Path, data: &[u8]) -> Result<(), FsError> {
        validate_relative_path(relative_path)?;
        let cow_path = self.cow_dir.join(relative_path);

        // Ensure parent directories exist in cow_dir.
        if let Some(parent) = cow_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                FsError::CowError(format!("create_dir_all failed: {e}"))
            })?;
        }

        // If not yet copied and it exists in source, do the CoW copy first
        // so we preserve the original metadata.  We only do this when the
        // file actually existed — for new files there is nothing to copy.
        if !self.copied_paths.contains(relative_path) {
            let src = self.source.join(relative_path);
            if src.exists() {
                std::fs::copy(&src, &cow_path).map_err(|e| {
                    FsError::CowError(format!("initial CoW copy failed: {e}"))
                })?;
                debug!(path = %relative_path.display(), "CoW: initial copy from source");
            }
            self.copied_paths.insert(relative_path.to_path_buf());
        }

        std::fs::write(&cow_path, data).map_err(FsError::Io)?;
        debug!(path = %relative_path.display(), bytes = data.len(), "CoW: write");
        Ok(())
    }

    /// Returns `true` if `relative_path` has been modified (or created) in the CoW layer.
    pub fn is_modified(&self, relative_path: &Path) -> bool {
        self.copied_paths.contains(relative_path)
    }

    /// Returns an iterator over every relative path that has been modified.
    pub fn modified_files(&self) -> Vec<&Path> {
        self.copied_paths.iter().map(PathBuf::as_path).collect()
    }

    /// Produce a structured diff between the CoW layer and `source`.
    pub fn diff(&self) -> Result<Vec<CowChange>, FsError> {
        let mut changes = Vec::new();

        for rel in &self.copied_paths {
            let cow_path = self.cow_dir.join(rel);
            let src_path = self.source.join(rel);

            let (change_type, size_bytes) = if !cow_path.exists() {
                // Marker for deletion (file removed in CoW layer).
                (ChangeType::Deleted, 0)
            } else {
                let size = std::fs::metadata(&cow_path)
                    .map(|m| m.len())
                    .unwrap_or(0);
                if src_path.exists() {
                    (ChangeType::Modified, size)
                } else {
                    (ChangeType::Added, size)
                }
            };

            changes.push(CowChange {
                path: rel.clone(),
                change_type,
                size_bytes,
            });
        }

        Ok(changes)
    }

    /// Discard all CoW changes — removes `cow_dir` contents and clears the
    /// tracked-paths set.
    pub fn discard(&mut self) -> Result<(), FsError> {
        if self.cow_dir.exists() {
            std::fs::remove_dir_all(&self.cow_dir).map_err(|e| {
                FsError::CowError(format!("discard failed: {e}"))
            })?;
            std::fs::create_dir_all(&self.cow_dir).map_err(|e| {
                FsError::CowError(format!("recreate cow_dir after discard failed: {e}"))
            })?;
        }
        self.copied_paths.clear();
        debug!("CoW changes discarded");
        Ok(())
    }

    /// Commit all CoW changes back into `source`.  After a successful commit
    /// the CoW layer is cleared.
    pub fn commit(&mut self) -> Result<(), FsError> {
        for rel in self.copied_paths.iter() {
            let cow_path = self.cow_dir.join(rel);
            let dst = self.source.join(rel);

            if !cow_path.exists() {
                // Treat a missing CoW path as a deletion.
                if dst.exists() {
                    std::fs::remove_file(&dst).map_err(FsError::Io)?;
                }
                continue;
            }

            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent).map_err(FsError::Io)?;
            }
            std::fs::copy(&cow_path, &dst).map_err(FsError::Io)?;
        }

        let count = self.copied_paths.len();
        self.discard()?;
        debug!(count, "CoW changes committed to source");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::validate_relative_path;
    use std::path::Path;

    #[test]
    fn validate_rejects_absolute_path() {
        assert!(validate_relative_path(Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn validate_rejects_dot_dot() {
        assert!(validate_relative_path(Path::new("../escape")).is_err());
        assert!(validate_relative_path(Path::new("sub/../../escape")).is_err());
    }

    #[test]
    fn validate_accepts_relative() {
        assert!(validate_relative_path(Path::new("src/main.rs")).is_ok());
        assert!(validate_relative_path(Path::new("file.txt")).is_ok());
        assert!(validate_relative_path(Path::new("a/b/c/d")).is_ok());
    }

    #[test]
    fn validate_rejects_null_bytes() {
        assert!(validate_relative_path(Path::new("file\0.txt")).is_err());
    }
}
