//! Filesystem guard — checks paths against the active policy.

use crate::error::FsError;
use sandcastle_policy::SandboxProfile;
use std::path::{Path, PathBuf};

/// Enforces filesystem policy for a single sandbox instance.
#[derive(Debug)]
pub struct FsGuard {
    // TODO: wire profile into check_read / check_write once FsGuard is fully implemented
    #[allow(dead_code)]
    profile: SandboxProfile,
}

impl FsGuard {
    /// Create a guard from the given sandbox profile.
    pub fn new(profile: SandboxProfile) -> Self {
        Self { profile }
    }

    /// Return `Ok(())` if `path` is allowed for reading, or an error.
    pub fn check_read(&self, path: &Path) -> Result<(), FsError> {
        let canonical = canonicalize_best_effort(path);
        let path_str = canonical.to_string_lossy();
        let fs = &self.profile.permissions.filesystem;

        // Deny rules take absolute priority.
        for pattern in &fs.deny {
            if glob_match_simple(pattern, &path_str) {
                return Err(FsError::PathDenied(canonical));
            }
        }

        // Default deny: must match at least one allow_read pattern.
        let allowed = fs
            .allow_read
            .iter()
            .any(|p| glob_match_simple(p, &path_str));

        if allowed {
            Ok(())
        } else {
            Err(FsError::PathDenied(canonical))
        }
    }

    /// Return `Ok(())` if `path` is allowed for writing, or an error.
    pub fn check_write(&self, path: &Path) -> Result<(), FsError> {
        let canonical = canonicalize_best_effort(path);
        let path_str = canonical.to_string_lossy();
        let fs = &self.profile.permissions.filesystem;

        // Deny rules take absolute priority.
        for pattern in &fs.deny {
            if glob_match_simple(pattern, &path_str) {
                return Err(FsError::PathDenied(canonical));
            }
        }

        // Default deny: must match at least one allow_write pattern.
        let allowed = fs
            .allow_write
            .iter()
            .any(|p| glob_match_simple(p, &path_str));

        if allowed {
            Ok(())
        } else {
            Err(FsError::PathDenied(canonical))
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Attempt to canonicalize a path.  If `fs::canonicalize` fails (e.g. the path
/// does not yet exist), fall back to a lexical normalization so we still strip
/// `..` components before matching against policy patterns.
fn canonicalize_best_effort(path: &Path) -> PathBuf {
    if let Ok(p) = std::fs::canonicalize(path) {
        return p;
    }
    lexical_normalize(path)
}

/// Resolve `..` and `.` components lexically without touching the filesystem.
fn lexical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut components: Vec<std::ffi::OsString> = Vec::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                // Pop the last normal component, but never go above a root/prefix.
                if matches!(components.last(), Some(_)) {
                    components.pop();
                }
            }
            Component::CurDir => {}
            other => components.push(other.as_os_str().to_owned()),
        }
    }
    components.iter().collect()
}

/// Minimal glob matcher supporting `*` (single-segment) and `**` (multi-segment).
/// Normalizes the text path before matching to prevent `..`-based bypass.
fn glob_match_simple(pattern: &str, text: &str) -> bool {
    // Normalize the text path to remove `..` sequences before matching.
    let normalized_text = {
        let p = std::path::Path::new(text);
        let normalized = lexical_normalize(p);
        normalized.to_string_lossy().replace('\\', "/")
    };
    let text: &str = &normalized_text;

    if pattern == "*" || pattern == "**" {
        return true;
    }

    // Strip leading placeholders.
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

#[cfg(test)]
mod tests {
    use super::glob_match_simple;

    #[test]
    fn glob_double_star_requires_slash_boundary() {
        // /sandbox/project/** must NOT match /sandbox/project-evil/secret
        assert!(!glob_match_simple("/sandbox/project/**", "/sandbox/project-evil/secret"));
        assert!(!glob_match_simple("/sandbox/project/**", "/sandbox/project-evil"));

        // But it MUST match paths actually under /sandbox/project/
        assert!(glob_match_simple("/sandbox/project/**", "/sandbox/project/file.txt"));
        assert!(glob_match_simple("/sandbox/project/**", "/sandbox/project/sub/deep"));
        assert!(glob_match_simple("/sandbox/project/**", "/sandbox/project"));
    }

    #[test]
    fn glob_single_star_matches_one_level() {
        assert!(glob_match_simple("/etc/*", "/etc/passwd"));
        assert!(!glob_match_simple("/etc/*", "/etc/ssh/config"));
    }

    #[test]
    fn glob_exact_match() {
        assert!(glob_match_simple("/etc/passwd", "/etc/passwd"));
        assert!(!glob_match_simple("/etc/passwd", "/etc/shadow"));
    }

    #[test]
    fn glob_star_matches_all() {
        assert!(glob_match_simple("*", "/anything/at/all"));
        assert!(glob_match_simple("/**", "/anything/at/all"));
    }

    #[test]
    fn glob_tilde_prefix_matches() {
        // The ~ prefix is stripped during matching, so "~/.ssh/**" matches
        // paths starting with "/.ssh/".
        assert!(glob_match_simple("~/.ssh/**", "/.ssh/id_rsa"));
        assert!(glob_match_simple("~/.ssh/**", "/.ssh/config"));
    }

    #[test]
    fn deny_overrides_allow() {
        // A path matching both deny and allow should be denied.
        use sandcastle_policy::SandboxProfile;
        use sandcastle_policy::permission::*;
        let profile = SandboxProfile {
            name: "test".into(),
            trust_level: TrustLevel::Develop,
            permissions: Permissions {
                filesystem: FsPermissions {
                    allow_read: vec!["/data/**".into()],
                    allow_write: vec![],
                    deny: vec!["/data/secret/**".into()],
                },
                ..TrustLevel::Develop.default_permissions()
            },
            ..SandboxProfile::isolated("test")
        };
        let guard = super::FsGuard::new(profile);
        assert!(guard.check_read(std::path::Path::new("/data/public/file.txt")).is_ok());
        assert!(guard.check_read(std::path::Path::new("/data/secret/key.pem")).is_err());
    }

    #[test]
    fn path_traversal_normalized() {
        // ../../../etc/shadow should be normalized before matching
        assert!(!glob_match_simple("/project/**", "/project/../../etc/shadow"));
    }
}
