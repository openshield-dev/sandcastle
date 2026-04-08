//! Profile resolver — looks up and loads [`SandboxProfile`] by name.
//!
//! Resolution order:
//! 1. Built-in profiles (matched by well-known name).
//! 2. `sandcastle.yaml` files found in the configured search paths.

use std::path::{Path, PathBuf};

use crate::error::PolicyError;
use crate::profile::{BuiltinProfile, SandboxProfile};

/// Maps well-known command substrings to built-in profiles.
///
/// Each entry is a (needle, profile) pair. The needle is matched against the
/// command string with a simple `contains` check; first match wins.
static COMMAND_MAP: &[(&str, BuiltinProfile)] = &[
    ("claude", BuiltinProfile::ClaudeCode),
    ("codex", BuiltinProfile::Codex),
    ("langchain", BuiltinProfile::LangChain),
    ("ollama", BuiltinProfile::Ollama),
    ("openclaw", BuiltinProfile::OpenClaw),
];

/// Resolves sandbox profiles from built-in definitions or YAML files on disk.
pub struct ProfileResolver {
    /// Directories to search for `sandcastle.yaml` profile files.
    search_paths: Vec<PathBuf>,
}

impl ProfileResolver {
    /// Create a new resolver that will search the given directories.
    pub fn new(search_paths: Vec<PathBuf>) -> Self {
        Self { search_paths }
    }

    /// Resolve a profile by name.
    ///
    /// Checks built-in profiles first (case-insensitive), then walks
    /// `search_paths` looking for a `sandcastle.yaml` whose top-level `name`
    /// field matches.
    pub fn resolve(&self, name: &str) -> Result<SandboxProfile, PolicyError> {
        // 1. Check built-in profiles.
        if let Some(builtin) = Self::match_builtin(name) {
            tracing::debug!(name, "Resolved profile from built-ins");
            return Ok(builtin.to_profile());
        }

        // 2. Walk search paths looking for sandcastle.yaml files.
        for dir in &self.search_paths {
            let candidate = dir.join("sandcastle.yaml");
            if candidate.exists() {
                match Self::load_from_file(&candidate) {
                    Ok(profile) if profile.name.eq_ignore_ascii_case(name) => {
                        tracing::debug!(
                            name,
                            path = %candidate.display(),
                            "Resolved profile from file"
                        );
                        return Ok(profile);
                    }
                    Ok(_) => {} // name doesn't match, keep looking
                    Err(e) => {
                        tracing::error!(
                            path = %candidate.display(),
                            error = %e,
                            "Skipping unreadable profile file"
                        );
                    }
                }
            }
        }

        Err(PolicyError::ProfileNotFound(name.to_owned()))
    }

    /// Parse a YAML file at `path` into a [`SandboxProfile`].
    pub fn load_from_file(path: &Path) -> Result<SandboxProfile, PolicyError> {
        let content = std::fs::read_to_string(path)?;
        let profile: SandboxProfile = serde_yaml::from_str(&content)?;
        Ok(profile)
    }

    /// Detect which built-in profile best matches the command being run.
    ///
    /// Returns `None` when no known agent is recognised.
    ///
    /// # Examples
    /// ```
    /// use sandcastle_policy::resolver::ProfileResolver;
    /// use sandcastle_policy::profile::BuiltinProfile;
    ///
    /// assert_eq!(ProfileResolver::auto_detect("claude"), Some(BuiltinProfile::ClaudeCode));
    /// assert_eq!(ProfileResolver::auto_detect("ollama serve"), Some(BuiltinProfile::Ollama));
    /// assert_eq!(ProfileResolver::auto_detect("vim"), None);
    /// ```
    pub fn auto_detect(command: &str) -> Option<BuiltinProfile> {
        let lower = command.to_lowercase();
        // Extract the binary name from the command: take the first whitespace-
        // delimited token (the executable path), then grab the last path component
        // (after `/` or `\`). This prevents paths like `/tmp/malicious-claude-worm`
        // from matching the "claude" needle via a naive `contains` check.
        let exe_token = lower.split_whitespace().next().unwrap_or(&lower);
        let binary_name = exe_token
            .rsplit(|c: char| c == '/' || c == '\\')
            .next()
            .unwrap_or(exe_token);
        for (needle, profile) in COMMAND_MAP {
            if binary_name == *needle || binary_name.starts_with(&format!("{}.", needle)) {
                return Some(profile.clone());
            }
        }
        None
    }

    // --- private helpers ----------------------------------------------------

    fn match_builtin(name: &str) -> Option<BuiltinProfile> {
        match name.to_lowercase().as_str() {
            "claude-code" | "claudecode" | "claude_code" => Some(BuiltinProfile::ClaudeCode),
            "codex" => Some(BuiltinProfile::Codex),
            "langchain" | "lang-chain" => Some(BuiltinProfile::LangChain),
            "ollama" => Some(BuiltinProfile::Ollama),
            "openclaw" | "open-claw" | "open_claw" => Some(BuiltinProfile::OpenClaw),
            _ => None,
        }
    }
}
