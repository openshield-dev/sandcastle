//! OverlayFS management for sandboxed filesystem views.
//!
//! On Linux, `mount` and `unmount` issue real `mount(2)` / `umount(2)` syscalls.
//! On other platforms they log a warning and simulate the overlay by copying the
//! lower layer into the merged directory so the rest of the code can exercise the
//! same paths in CI.

use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::error::FsError;

/// An OverlayFS mount with lower (read-only), upper (writable), work, and merged layers.
#[derive(Debug, Clone)]
pub struct OverlayMount {
    /// Read-only base layer(s). Multiple lower dirs are separated by `:` in the mount options.
    pub lower_dirs: Vec<PathBuf>,
    /// Writable upper layer — captures all modifications made inside the sandbox.
    pub upper_dir: PathBuf,
    /// Work directory required by the kernel's overlay implementation.
    pub work_dir: PathBuf,
    /// Merged view presented to the sandboxed process.
    pub merged_dir: PathBuf,
    /// Whether this overlay is currently mounted.
    pub mounted: bool,
}

impl OverlayMount {
    /// Create a new (not yet mounted) overlay descriptor.
    pub fn new(
        lower: Vec<PathBuf>,
        upper: PathBuf,
        work: PathBuf,
        merged: PathBuf,
    ) -> Self {
        OverlayMount {
            lower_dirs: lower,
            upper_dir: upper,
            work_dir: work,
            merged_dir: merged,
            mounted: false,
        }
    }

    /// Mount the overlay filesystem.
    ///
    /// On Linux this calls the real `mount` command with `overlay` type.
    /// On other platforms it logs a warning and copies the first lower layer
    /// into `merged_dir` so the directory is usable.
    pub fn mount(&mut self) -> Result<(), FsError> {
        if self.mounted {
            return Ok(());
        }

        // Ensure all required directories exist.
        for dir in [&self.upper_dir, &self.work_dir, &self.merged_dir] {
            std::fs::create_dir_all(dir).map_err(|e| FsError::MountFailed {
                path: dir.clone(),
                reason: e.to_string(),
            })?;
        }

        #[cfg(target_os = "linux")]
        {
            self.mount_linux()?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            self.mount_simulated()?;
        }

        self.mounted = true;
        info!(merged = %self.merged_dir.display(), "overlay mounted");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn mount_linux(&self) -> Result<(), FsError> {
        use std::process::Command;

        let lower = self
            .lower_dirs
            .iter()
            .map(|p| p.to_string_lossy())
            .collect::<Vec<_>>()
            .join(":");

        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower,
            self.upper_dir.display(),
            self.work_dir.display(),
        );

        let status = Command::new("mount")
            .args(["-t", "overlay", "overlay", "-o", &options])
            .arg(&self.merged_dir)
            .status()
            .map_err(|e| FsError::MountFailed {
                path: self.merged_dir.clone(),
                reason: e.to_string(),
            })?;

        if !status.success() {
            return Err(FsError::MountFailed {
                path: self.merged_dir.clone(),
                reason: format!("mount exited with {status}"),
            });
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn mount_simulated(&self) -> Result<(), FsError> {
        warn!(
            merged = %self.merged_dir.display(),
            "OverlayFS not available on this platform — simulating with directory copy"
        );

        // Copy the first (lowest) layer into merged so there is usable content.
        if let Some(lower) = self.lower_dirs.first() {
            if lower.exists() {
                copy_dir_all(lower, &self.merged_dir)?;
            }
        }

        Ok(())
    }

    /// Unmount the overlay.
    pub fn unmount(&mut self) -> Result<(), FsError> {
        if !self.mounted {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            use std::process::Command;

            let status = Command::new("umount")
                .arg(&self.merged_dir)
                .status()
                .map_err(|e| FsError::MountFailed {
                    path: self.merged_dir.clone(),
                    reason: e.to_string(),
                })?;

            if !status.success() {
                return Err(FsError::MountFailed {
                    path: self.merged_dir.clone(),
                    reason: format!("umount exited with {status}"),
                });
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            warn!(
                merged = %self.merged_dir.display(),
                "OverlayFS not available on this platform — skipping unmount"
            );
        }

        self.mounted = false;
        info!(merged = %self.merged_dir.display(), "overlay unmounted");
        Ok(())
    }

    /// Walk `upper_dir` and return relative paths of every file that was written.
    pub fn list_changes(&self) -> Result<Vec<PathBuf>, FsError> {
        let mut changes = Vec::new();
        if !self.upper_dir.exists() {
            return Ok(changes);
        }
        walk_relative(&self.upper_dir, &self.upper_dir, &mut changes)?;
        Ok(changes)
    }

    /// Sum the byte sizes of all files in `upper_dir`.
    pub fn changes_size(&self) -> Result<u64, FsError> {
        let mut total: u64 = 0;
        if !self.upper_dir.exists() {
            return Ok(total);
        }
        for entry in walkdir(&self.upper_dir)? {
            let meta = std::fs::metadata(&entry)?;
            if meta.is_file() {
                total += meta.len();
            }
        }
        Ok(total)
    }

    /// Discard all changes by clearing `upper_dir` and `work_dir`.
    pub fn discard_changes(&self) -> Result<(), FsError> {
        if self.upper_dir.exists() {
            std::fs::remove_dir_all(&self.upper_dir)?;
            std::fs::create_dir_all(&self.upper_dir)?;
        }
        if self.work_dir.exists() {
            std::fs::remove_dir_all(&self.work_dir)?;
            std::fs::create_dir_all(&self.work_dir)?;
        }
        info!(upper = %self.upper_dir.display(), "overlay changes discarded");
        Ok(())
    }

    /// Commit changes by copying every file in `upper_dir` into the first `lower_dir`.
    ///
    /// This is a best-effort operation; on production Linux systems you would
    /// typically snapshot / rsync instead.
    pub fn commit_changes(&self) -> Result<(), FsError> {
        let Some(lower) = self.lower_dirs.first() else {
            return Err(FsError::OverlayError(
                "no lower dir to commit changes into".into(),
            ));
        };

        let changes = self.list_changes()?;
        for rel in &changes {
            let src = self.upper_dir.join(rel);
            let dst = lower.join(rel);
            if let Some(parent) = dst.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&src, &dst)?;
        }

        info!(
            count = changes.len(),
            lower = %lower.display(),
            "overlay changes committed"
        );
        Ok(())
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Recursively collect absolute paths of every entry under `root`.
fn walkdir(root: &Path) -> Result<Vec<PathBuf>, FsError> {
    let mut out = Vec::new();
    collect_entries(root, &mut out)?;
    Ok(out)
}

fn collect_entries(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), FsError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        out.push(path.clone());
        if path.is_dir() {
            collect_entries(&path, out)?;
        }
    }
    Ok(())
}

/// Walk `root` and collect paths relative to `base`.
/// Symlinks are skipped to prevent following links outside the sandbox.
fn walk_relative(base: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), FsError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        // Use symlink_metadata so we inspect the link itself, not its target.
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            warn!(path = %entry.path().display(), "walk_relative: skipping symlink");
            continue;
        }
        let path = entry.path();
        let rel = path.strip_prefix(base).map_err(|e| {
            FsError::OverlayError(format!("strip_prefix failed: {e}"))
        })?;
        if file_type.is_dir() {
            walk_relative(base, &path, out)?;
        } else {
            out.push(rel.to_path_buf());
        }
    }
    Ok(())
}

/// Recursively copy `src` directory into `dst`.
/// Symlinks are skipped to prevent following links outside the sandbox.
#[cfg(not(target_os = "linux"))]
fn copy_dir_all(src: &Path, dst: &Path) -> Result<(), FsError> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        // Use symlink_metadata so we inspect the link itself, not its target.
        let meta = std::fs::symlink_metadata(entry.path())?;
        if meta.file_type().is_symlink() {
            warn!(path = %entry.path().display(), "copy_dir_all: skipping symlink");
            continue;
        }
        let target = dst.join(entry.file_name());
        if meta.is_dir() {
            copy_dir_all(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}
