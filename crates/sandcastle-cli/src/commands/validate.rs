//! Input validation helpers for CLI arguments.
//!
//! These functions reject values that could lead to path traversal, YAML
//! injection, overly-permissive wildcards, or other security issues.

/// Validate a user-supplied name (profile name, snapshot name, branch name).
///
/// Rejects empty names, names longer than 64 characters, names containing
/// path-traversal sequences, and names with characters outside the allowed set
/// (alphanumeric, hyphen, underscore, dot).
pub fn validate_name(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!name.is_empty(), "Name must not be empty");
    anyhow::ensure!(
        name.len() <= 64,
        "Name must be at most 64 characters (got {})",
        name.len()
    );
    anyhow::ensure!(
        !name.contains('\0'),
        "Name must not contain null bytes"
    );
    anyhow::ensure!(
        !name.contains(".."),
        "Name must not contain '..' sequences"
    );
    anyhow::ensure!(
        !name.contains('/') && !name.contains('\\'),
        "Name must not contain path separators ('/' or '\\')"
    );
    anyhow::ensure!(
        name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'),
        "Name must contain only alphanumeric characters, hyphens, underscores, and dots"
    );
    Ok(())
}

/// Validate a `--allow-dir` path argument.
///
/// Rejects paths containing `..` sequences (path traversal) and overly-broad
/// wildcard patterns.
pub fn validate_allow_dir(dir: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!dir.is_empty(), "--allow-dir path must not be empty");
    anyhow::ensure!(
        !dir.contains(".."),
        "--allow-dir path must not contain '..' sequences: {dir}"
    );
    anyhow::ensure!(
        dir != "*" && dir != "/**" && dir != "/*",
        "--allow-dir rejects wildcard-only paths ('{dir}') — be more specific"
    );
    Ok(())
}

/// Validate a `--allow-net` domain argument.
///
/// Rejects empty strings, a bare `*` (catch-all), and performs basic DNS format
/// checks.
pub fn validate_allow_domain(domain: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!domain.is_empty(), "--allow-net domain must not be empty");
    anyhow::ensure!(
        domain != "*",
        "--allow-net rejects bare '*' — use a specific domain or '*.example.com'"
    );

    // Basic DNS label validation: labels separated by dots, each label
    // alphanumeric + hyphens (leading wildcard label `*` is allowed).
    for (i, label) in domain.split('.').enumerate() {
        if i == 0 && label == "*" {
            // Leading wildcard label is acceptable (e.g., *.example.com).
            continue;
        }
        anyhow::ensure!(
            !label.is_empty(),
            "--allow-net domain has an empty label: {domain}"
        );
        anyhow::ensure!(
            label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "--allow-net domain label contains invalid characters: {label}"
        );
    }
    Ok(())
}

/// Validate that a mode string is one of the recognised sandbox modes.
pub fn validate_mode(mode: &str) -> anyhow::Result<()> {
    match mode {
        "enforce" | "audit" => Ok(()),
        other => anyhow::bail!(
            "Unknown mode '{other}'. Valid modes are: enforce, audit"
        ),
    }
}
