//! Bind mount management for sandbox filesystem isolation.
//!
//! On Linux, `mount_all` / `unmount_all` issue real bind-mount syscalls via the
//! `mount` command.  On other platforms (macOS, Windows) the code falls back to
//! creating symbolic links (or on Windows, directory junctions) so that the
//! rest of the code can exercise the same paths in CI.

use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::error::FsError;

/// A single bind mount pairing a host `source` with a sandbox `target`.
#[derive(Debug, Clone)]
pub struct BindMount {
    pub source: PathBuf,
    pub target: PathBuf,
    pub read_only: bool,
    pub mounted: bool,
}

impl BindMount {
    pub fn new(source: PathBuf, target: PathBuf, read_only: bool) -> Self {
        BindMount {
            source,
            target,
            read_only,
            mounted: false,
        }
    }

    fn mount(&mut self) -> Result<(), FsError> {
        if self.mounted {
            return Ok(());
        }

        // Ensure the target mount-point exists.
        if self.source.is_dir() {
            std::fs::create_dir_all(&self.target).map_err(|e| FsError::MountFailed {
                path: self.target.clone(),
                reason: e.to_string(),
            })?;
        } else if let Some(parent) = self.target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| FsError::MountFailed {
                path: self.target.clone(),
                reason: e.to_string(),
            })?;
        }

        #[cfg(target_os = "linux")]
        self.mount_linux()?;

        #[cfg(not(target_os = "linux"))]
        self.mount_fallback()?;

        self.mounted = true;
        info!(
            source = %self.source.display(),
            target = %self.target.display(),
            read_only = self.read_only,
            "bind mount established"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn mount_linux(&self) -> Result<(), FsError> {
        use std::process::Command;

        // First bind-mount, then optionally remount read-only.
        let status = Command::new("mount")
            .args(["--bind", &self.source.to_string_lossy()])
            .arg(&self.target)
            .status()
            .map_err(|e| FsError::MountFailed {
                path: self.target.clone(),
                reason: e.to_string(),
            })?;

        if !status.success() {
            return Err(FsError::MountFailed {
                path: self.target.clone(),
                reason: format!("mount --bind exited with {status}"),
            });
        }

        if self.read_only {
            let ro_status = Command::new("mount")
                .args(["-o", "remount,ro,bind"])
                .arg(&self.target)
                .status()
                .map_err(|e| FsError::MountFailed {
                    path: self.target.clone(),
                    reason: e.to_string(),
                })?;

            if !ro_status.success() {
                return Err(FsError::MountFailed {
                    path: self.target.clone(),
                    reason: format!("remount ro exited with {ro_status}"),
                });
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn mount_fallback(&self) -> Result<(), FsError> {
        warn!(
            source = %self.source.display(),
            target = %self.target.display(),
            "bind mounts not available on this platform — creating symlink as fallback"
        );

        // Remove any existing target so symlink creation succeeds.
        if self.target.exists() || self.target.is_symlink() {
            if self.target.is_dir() && !self.target.is_symlink() {
                std::fs::remove_dir_all(&self.target).map_err(FsError::Io)?;
            } else {
                std::fs::remove_file(&self.target).map_err(FsError::Io)?;
            }
        }

        create_symlink(&self.source, &self.target).map_err(|e| FsError::MountFailed {
            path: self.target.clone(),
            reason: e.to_string(),
        })?;

        Ok(())
    }

    fn unmount(&mut self) -> Result<(), FsError> {
        if !self.mounted {
            return Ok(());
        }

        #[cfg(target_os = "linux")]
        {
            use std::process::Command;
            let status = Command::new("umount")
                .arg(&self.target)
                .status()
                .map_err(|e| FsError::MountFailed {
                    path: self.target.clone(),
                    reason: e.to_string(),
                })?;

            if !status.success() {
                return Err(FsError::MountFailed {
                    path: self.target.clone(),
                    reason: format!("umount exited with {status}"),
                });
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            warn!(
                target = %self.target.display(),
                "bind mounts not available on this platform — removing symlink"
            );
            if self.target.is_symlink() {
                std::fs::remove_file(&self.target).map_err(FsError::Io)?;
            }
        }

        self.mounted = false;
        info!(target = %self.target.display(), "bind mount removed");
        Ok(())
    }
}

/// Manages a collection of bind mounts for a single sandbox.
#[derive(Debug)]
pub struct BindMountSet {
    mounts: Vec<BindMount>,
}

impl Default for BindMountSet {
    fn default() -> Self {
        Self::new()
    }
}

impl BindMountSet {
    pub fn new() -> Self {
        BindMountSet { mounts: Vec::new() }
    }

    /// Register a bind mount; it will be applied when [`mount_all`] is called.
    pub fn add(&mut self, source: PathBuf, target: PathBuf, read_only: bool) {
        self.mounts.push(BindMount::new(source, target, read_only));
    }

    /// Mount all registered bind mounts in registration order.
    pub fn mount_all(&mut self) -> Result<(), FsError> {
        for mount in &mut self.mounts {
            mount.mount()?;
        }
        Ok(())
    }

    /// Unmount all registered bind mounts in reverse registration order.
    pub fn unmount_all(&mut self) -> Result<(), FsError> {
        let mut errors: Vec<String> = Vec::new();

        for mount in self.mounts.iter_mut().rev() {
            if let Err(e) = mount.unmount() {
                errors.push(e.to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(FsError::TeardownError(errors.join("; ")))
        }
    }

    /// Returns an iterator over all registered mounts.
    pub fn mounts(&self) -> &[BindMount] {
        &self.mounts
    }
}

// ── platform helpers ──────────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
fn create_symlink(src: &Path, dst: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        // Use directory junction for directories, symlink for files.
        if src.is_dir() {
            std::os::windows::fs::symlink_dir(src, dst)
        } else {
            std::os::windows::fs::symlink_file(src, dst)
        }
    }

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(src, dst)
    }

    #[cfg(not(any(windows, unix)))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "symlinks not supported on this platform",
        ))
    }
}
