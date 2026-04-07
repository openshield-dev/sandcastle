//! Temporary filesystem (tmpfs) management for ephemeral sandbox storage.
//!
//! On Linux a real `tmpfs` is mounted at `mount_point` with an optional
//! `size=` cap.  On other platforms [`tempfile::TempDir`] is used as a
//! portable fallback so the rest of the code can exercise the same API.

use std::path::PathBuf;
use tracing::{info, warn};

use crate::error::FsError;

/// Disk-usage snapshot for a tmpfs mount.
pub struct TmpfsUsage {
    pub used_bytes: u64,
    pub total_bytes: u64,
}

/// Manages a tmpfs mount for ephemeral sandbox storage.
#[derive(Debug)]
pub struct TmpfsMount {
    pub mount_point: PathBuf,
    /// Optional upper bound in bytes (`size=` mount option on Linux).
    pub size_limit: Option<u64>,
    pub mounted: bool,
    /// Non-Linux fallback: the `TempDir` keeps the directory alive.
    #[cfg(not(target_os = "linux"))]
    _temp_dir: Option<tempfile::TempDir>,
}

impl TmpfsMount {
    pub fn new(mount_point: PathBuf, size_limit: Option<u64>) -> Self {
        TmpfsMount {
            mount_point,
            size_limit,
            mounted: false,
            #[cfg(not(target_os = "linux"))]
            _temp_dir: None,
        }
    }

    /// Mount (or create) the temporary filesystem.
    pub fn mount(&mut self) -> Result<(), FsError> {
        if self.mounted {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        self.mount_linux()?;

        #[cfg(not(target_os = "linux"))]
        self.mount_fallback()?;

        self.mounted = true;
        info!(mount_point = %self.mount_point.display(), "tmpfs mounted");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn mount_linux(&self) -> Result<(), FsError> {
        use std::process::Command;

        std::fs::create_dir_all(&self.mount_point).map_err(|e| FsError::MountFailed {
            path: self.mount_point.clone(),
            reason: e.to_string(),
        })?;

        let mut options = String::from("rw,nosuid,nodev");
        if let Some(limit) = self.size_limit {
            options.push_str(&format!(",size={limit}"));
        }

        let status = Command::new("mount")
            .args(["-t", "tmpfs", "tmpfs", "-o", &options])
            .arg(&self.mount_point)
            .status()
            .map_err(|e| FsError::MountFailed {
                path: self.mount_point.clone(),
                reason: e.to_string(),
            })?;

        if !status.success() {
            return Err(FsError::MountFailed {
                path: self.mount_point.clone(),
                reason: format!("mount tmpfs exited with {status}"),
            });
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn mount_fallback(&mut self) -> Result<(), FsError> {
        warn!(
            mount_point = %self.mount_point.display(),
            "tmpfs not available on this platform — using tempfile::TempDir as fallback"
        );

        if self.mount_point.as_os_str().is_empty() {
            let dir = tempfile::TempDir::new().map_err(|e| FsError::TmpfsError(e.to_string()))?;
            self.mount_point = dir.path().to_path_buf();
            self._temp_dir = Some(dir);
        } else {
            std::fs::create_dir_all(&self.mount_point).map_err(|e| FsError::MountFailed {
                path: self.mount_point.clone(),
                reason: e.to_string(),
            })?;
        }

        Ok(())
    }

    /// Unmount (or clean up) the temporary filesystem.
    pub fn unmount(&mut self) -> Result<(), FsError> {
        if !self.mounted {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            let status = Command::new("umount")
                .arg(&self.mount_point)
                .status()
                .map_err(|e| FsError::MountFailed {
                    path: self.mount_point.clone(),
                    reason: e.to_string(),
                })?;

            if !status.success() {
                return Err(FsError::MountFailed {
                    path: self.mount_point.clone(),
                    reason: format!("umount tmpfs exited with {status}"),
                });
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            warn!(
                mount_point = %self.mount_point.display(),
                "tmpfs not available on this platform — dropping TempDir fallback"
            );
            self._temp_dir = None;
            if self.mount_point.exists() {
                let _ = std::fs::remove_dir_all(&self.mount_point);
            }
        }

        self.mounted = false;
        info!(mount_point = %self.mount_point.display(), "tmpfs unmounted");
        Ok(())
    }

    /// Return current usage statistics for the tmpfs.
    pub fn usage(&self) -> Result<TmpfsUsage, FsError> {
        let used_bytes = dir_size(&self.mount_point)?;
        let total_bytes = self.size_limit.unwrap_or(used_bytes);
        Ok(TmpfsUsage { used_bytes, total_bytes })
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Recursively sum the sizes of all regular files under `dir`.
fn dir_size(dir: &std::path::Path) -> Result<u64, FsError> {
    let mut total = 0u64;
    if !dir.exists() {
        return Ok(total);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_symlink() {
            continue;
        }
        if path.is_dir() {
            total += dir_size(&path)?;
        } else {
            total += std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        }
    }
    Ok(total)
}
