//! High-level filesystem isolation orchestrator.
//!
//! [`FsIsolation`] coordinates overlays, bind mounts, tmpfs volumes, and the
//! copy-on-write layer into a single setup / teardown lifecycle, driven by a
//! [`sandcastle_policy::permission::Permissions`] value.

use std::path::{Path, PathBuf};
use tracing::{info, warn};

use sandcastle_policy::permission::Permissions;

use crate::{
    bind::BindMountSet,
    cow::CowDirectory,
    error::FsError,
    overlay::OverlayMount,
    tmpfs::TmpfsMount,
};

/// Orchestrates all filesystem isolation components for a single sandbox instance.
#[derive(Debug)]
pub struct FsIsolation {
    pub overlay: Option<OverlayMount>,
    pub binds: BindMountSet,
    pub tmpfs: Vec<TmpfsMount>,
    pub cow: Option<CowDirectory>,
    pub sandbox_root: PathBuf,
    /// Flattened allow-read glob patterns from the active permissions.
    allow_read: Vec<String>,
    /// Flattened allow-write glob patterns from the active permissions.
    allow_write: Vec<String>,
    /// Deny glob patterns (take priority over allow rules).
    deny: Vec<String>,
}

impl FsIsolation {
    /// Construct filesystem isolation from a [`Permissions`] specification.
    ///
    /// The `sandbox_root` is the directory that will be used as the base for
    /// all relative paths inside the sandbox (e.g. `/var/lib/sandcastle/<id>`).
    pub fn from_permissions(permissions: &Permissions, sandbox_root: PathBuf) -> Result<Self, FsError> {
        let fs_perm = &permissions.filesystem;

        // Create the sandbox root if it does not exist yet.
        std::fs::create_dir_all(&sandbox_root).map_err(|e| FsError::MountFailed {
            path: sandbox_root.clone(),
            reason: e.to_string(),
        })?;

        let mut binds = BindMountSet::new();
        let mut tmpfs_mounts: Vec<TmpfsMount> = Vec::new();
        let mut overlay: Option<OverlayMount> = None;
        // For each writable path in the policy we set up an OverlayFS so the
        // sandbox gets a mutable view without touching the host filesystem.
        // For the first writable path we create a full overlay; subsequent
        // writable paths become bind mounts into the merged view.
        let write_paths = resolve_glob_roots(&fs_perm.allow_write);

        if !write_paths.is_empty() {
            let lower_dirs: Vec<PathBuf> = write_paths
                .iter()
                .filter(|p| p.exists())
                .cloned()
                .collect();

            if !lower_dirs.is_empty() {
                let upper = sandbox_root.join("overlay/upper");
                let work  = sandbox_root.join("overlay/work");
                let merged = sandbox_root.join("overlay/merged");

                overlay = Some(OverlayMount::new(lower_dirs, upper, work, merged));
            }
        }

        // Read-only paths become read-only bind mounts.
        for read_path in resolve_glob_roots(&fs_perm.allow_read) {
            if read_path.exists() {
                // Skip if it is already covered by the overlay lower dir.
                let already_in_overlay = overlay
                    .as_ref()
                    .map(|o| o.lower_dirs.contains(&read_path))
                    .unwrap_or(false);

                if !already_in_overlay {
                    let rel = path_to_rel_target(&read_path);
                    let target = sandbox_root.join("mounts").join(rel);
                    binds.add(read_path, target, true);
                }
            } else {
                warn!(path = %read_path.display(), "allow_read path does not exist — skipping bind");
            }
        }

        // Provide a tmpfs scratch space at <sandbox_root>/tmp for ephemeral writes.
        let tmp_mount = sandbox_root.join("tmp");
        let size_limit = parse_size_limit(permissions.resources.max_disk.as_deref());
        tmpfs_mounts.push(TmpfsMount::new(tmp_mount, size_limit));

        // Set up a CoW directory over the sandbox root for tracking writes.
        let cow_dir = sandbox_root.join("cow");
        let cow = Some(CowDirectory::new(sandbox_root.clone(), cow_dir)?);

        info!(
            sandbox_root = %sandbox_root.display(),
            "FsIsolation constructed"
        );

        Ok(FsIsolation {
            overlay,
            binds,
            tmpfs: tmpfs_mounts,
            cow,
            sandbox_root,
            allow_read: fs_perm.allow_read.clone(),
            allow_write: fs_perm.allow_write.clone(),
            deny: fs_perm.deny.clone(),
        })
    }

    /// Mount all isolation layers (overlay → bind mounts → tmpfs).
    pub fn setup(&mut self) -> Result<(), FsError> {
        if let Some(ref mut overlay) = self.overlay {
            overlay.mount()?;
        }

        self.binds.mount_all()?;

        for tmpfs in &mut self.tmpfs {
            tmpfs.mount()?;
        }

        info!(sandbox_root = %self.sandbox_root.display(), "FsIsolation setup complete");
        Ok(())
    }

    /// Unmount all isolation layers in reverse order (tmpfs → bind mounts → overlay).
    pub fn teardown(&mut self) -> Result<(), FsError> {
        let mut errors: Vec<String> = Vec::new();

        for tmpfs in self.tmpfs.iter_mut().rev() {
            if let Err(e) = tmpfs.unmount() {
                errors.push(format!("tmpfs {}: {e}", tmpfs.mount_point.display()));
            }
        }

        if let Err(e) = self.binds.unmount_all() {
            errors.push(format!("bind mounts: {e}"));
        }

        if let Some(ref mut overlay) = self.overlay {
            if let Err(e) = overlay.unmount() {
                errors.push(format!("overlay: {e}"));
            }
        }

        if errors.is_empty() {
            info!(sandbox_root = %self.sandbox_root.display(), "FsIsolation teardown complete");
            Ok(())
        } else {
            Err(FsError::TeardownError(errors.join("; ")))
        }
    }

    /// Check whether `path` is permitted for the requested operation.
    ///
    /// Deny rules are checked first and always win.  Then allow rules are
    /// checked; a path is permitted only if at least one allow rule matches.
    pub fn check_access(&self, path: &Path, write: bool) -> bool {
        let path_str = path.to_string_lossy();

        // Deny rules take absolute priority.
        for pattern in &self.deny {
            if glob_match(pattern, &path_str) {
                return false;
            }
        }

        let allow_patterns = if write {
            &self.allow_write
        } else {
            &self.allow_read
        };

        // A path that matches no allow rule is denied by default.
        allow_patterns
            .iter()
            .any(|pattern| glob_match(pattern, &path_str))
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Expand a list of glob-style path specs to their "root" directories
/// (everything before the first `*` or `**` component).
fn resolve_glob_roots(patterns: &[String]) -> Vec<PathBuf> {
    patterns
        .iter()
        .map(|p| {
            // Strip environment-variable placeholders like `$PROJECT_DIR`.
            let p = p
                .trim_start_matches("$PROJECT_DIR")
                .trim_start_matches("~");

            // Take everything up to the first wildcard component.
            let root: PathBuf = p
                .split('/')
                .take_while(|seg| !seg.contains('*'))
                .collect::<Vec<_>>()
                .join("/")
                .into();

            if root.as_os_str().is_empty() {
                PathBuf::from("/")
            } else {
                root
            }
        })
        .collect()
}

/// Convert an absolute path to a relative slug suitable for use as a mount-point
/// subdirectory name (e.g. `/etc/resolv.conf` → `etc/resolv.conf`).
fn path_to_rel_target(path: &Path) -> PathBuf {
    path.components()
        .filter(|c| matches!(c, std::path::Component::Normal(_)))
        .collect()
}

/// Minimal glob matcher supporting `*` (single-segment wildcard) and `**`
/// (multi-segment wildcard).  Returns `true` if `pattern` matches `text`.
fn glob_match(pattern: &str, text: &str) -> bool {
    // Delegate to the `glob` crate if it is available; otherwise fall back to
    // a simple prefix / suffix check that handles the most common patterns.
    glob_match_simple(pattern, text)
}

fn glob_match_simple(pattern: &str, text: &str) -> bool {
    // Normalize the text path by resolving `..` components lexically so that
    // patterns cannot be bypassed via path traversal sequences.
    let normalized = lexical_normalize_path(text);
    let text: &str = &normalized;

    // Handle wildcard-everything patterns.
    if pattern == "*" || pattern == "**" {
        return true;
    }

    // Strip leading ~ and $PROJECT_DIR placeholders.
    let pattern = pattern
        .trim_start_matches("$PROJECT_DIR")
        .trim_start_matches('~');

    if pattern.ends_with("/**") || pattern.ends_with("/**/*") {
        let prefix = pattern.trim_end_matches("/**/*").trim_end_matches("/**");
        // Exact match on the prefix itself, or text is under prefix/.
        return text == prefix || text.starts_with(&format!("{prefix}/"));
    }

    if pattern.ends_with("/*") {
        let prefix = pattern.trim_end_matches("/*");
        let suffix = text.trim_start_matches(prefix);
        return text.starts_with(prefix)
            && (suffix.is_empty() || (suffix.starts_with('/') && !suffix[1..].contains('/')));
    }

    // Exact match.
    text == pattern
}

/// Resolve `..` and `.` components in a path string lexically, without
/// touching the filesystem.  Keeps the leading `/` for absolute paths.
fn lexical_normalize_path(text: &str) -> String {
    use std::path::Component;
    let path = std::path::Path::new(text);
    let mut parts: Vec<std::ffi::OsString> = Vec::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                // Only pop a Normal segment; never remove root or prefix.
                if matches!(parts.last().and_then(|s: &std::ffi::OsString| {
                    std::path::Path::new(s).components().next()
                }), Some(Component::Normal(_))) {
                    parts.pop();
                }
            }
            Component::CurDir => {}
            other => parts.push(other.as_os_str().to_owned()),
        }
    }
    // Always use forward slashes for cross-platform matching consistency.
    parts.iter().collect::<std::path::PathBuf>().to_string_lossy().replace('\\', "/")
}

/// Parse a human-readable size string like "10GB" into bytes.
fn parse_size_limit(s: Option<&str>) -> Option<u64> {
    let s = s?;
    let s = s.trim();

    let (num_part, unit) = s
        .find(|c: char| c.is_alphabetic())
        .map(|i| (&s[..i], &s[i..]))
        .unwrap_or((s, ""));

    let base: u64 = num_part.trim().parse().ok()?;
    let multiplier: u64 = match unit.to_uppercase().as_str() {
        "KB" | "K" => 1_024,
        "MB" | "M" => 1_024 * 1_024,
        "GB" | "G" => 1_024 * 1_024 * 1_024,
        "TB" | "T" => 1_024 * 1_024 * 1_024 * 1_024,
        _ => 1,
    };

    Some(base * multiplier)
}
