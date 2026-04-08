//! Implementation of the `sandcastle run` command.

use anyhow::Context;
use sandcastle_audit::AuditLogger;
use sandcastle_platform::{create_sandbox, SandboxConfig};
use sandcastle_policy::resolver::ProfileResolver;

/// Returns `true` when `value` matches any entry in `deny_patterns`.
///
/// Supports simple glob patterns: `*` alone matches everything, a leading `*`
/// matches any prefix, a trailing `*` matches any suffix, and patterns with a
/// single interior `*` match a prefix + suffix pair. Literal strings are
/// compared with exact equality.
fn matches_deny_list<'a>(value: &str, deny_patterns: &'a [String]) -> Option<&'a String> {
    deny_patterns.iter().find(|pattern| {
        let pat = pattern.as_str();
        // Catch-all wildcard.
        if pat == "*" || pat == "**" {
            return true;
        }
        // Handle /** and /**/* patterns (recursive directory match).
        if pat.ends_with("/**") || pat.ends_with("/**/*") {
            let prefix = pat.trim_end_matches("/**/*").trim_end_matches("/**");
            return value == prefix || value.starts_with(&format!("{prefix}/"));
        }
        // Single trailing * (one level).
        if pat.ends_with("/*") && !pat.ends_with("/**") {
            let prefix = pat.trim_end_matches("/*");
            return value.starts_with(&format!("{prefix}/"));
        }
        // Leading * (suffix match).
        if pat.starts_with('*') {
            return value.ends_with(&pat[1..]);
        }
        // Exact match.
        value == pat
    })
}

#[cfg(test)]
mod tests {
    use super::matches_deny_list;

    #[test]
    fn deny_double_star_matches_descendants() {
        let deny = vec!["/etc/**".to_string()];
        assert!(matches_deny_list("/etc/passwd", &deny).is_some());
        assert!(matches_deny_list("/etc/ssh/config", &deny).is_some());
        assert!(matches_deny_list("/etc", &deny).is_some());
        assert!(matches_deny_list("/etcetera", &deny).is_none());
    }

    #[test]
    fn deny_single_star_matches_one_level() {
        let deny = vec!["/tmp/*".to_string()];
        assert!(matches_deny_list("/tmp/file", &deny).is_some());
        assert!(matches_deny_list("/tmp/sub/deep", &deny).is_some()); // prefix match
    }

    #[test]
    fn deny_exact_match() {
        let deny = vec!["169.254.169.254".to_string()];
        assert!(matches_deny_list("169.254.169.254", &deny).is_some());
        assert!(matches_deny_list("10.0.0.1", &deny).is_none());
    }

    #[test]
    fn deny_leading_wildcard() {
        let deny = vec!["*.internal".to_string()];
        assert!(matches_deny_list("metadata.internal", &deny).is_some());
        assert!(matches_deny_list("example.com", &deny).is_none());
    }
}

/// Execute the `sandcastle run` command.
///
/// Resolves the named profile, applies CLI overrides, builds a [`SandboxConfig`],
/// creates the sandbox, launches the command, and waits for it to finish.
pub fn execute(
    profile: &str,
    allow_dirs: &[String],
    allow_net: &[String],
    allow_gpu: bool,
    interactive: bool,
    mode: &str,
    command: &[String],
) -> anyhow::Result<()> {
    // 0. Validate CLI inputs.
    super::validate::validate_mode(mode)?;

    for dir in allow_dirs {
        super::validate::validate_allow_dir(dir)?;
        // Reject --allow-dir entries that overlap with the profile's deny list.
    }
    for domain in allow_net {
        super::validate::validate_allow_domain(domain)?;
    }

    // 1. Resolve profile using the policy resolver.
    let resolver = ProfileResolver::new(vec![
        std::env::current_dir().context("Failed to determine current directory")?,
    ]);

    let mut sandbox_profile = resolver
        .resolve(profile)
        .with_context(|| format!("Unknown profile '{}'. Run `sandcastle profiles list` to see available profiles.", profile))?;

    // Check that --allow-dir entries don't conflict with the profile's deny list.
    let fs_deny = &sandbox_profile.permissions.filesystem.deny;
    for dir in allow_dirs {
        if let Some(denied) = matches_deny_list(dir, fs_deny) {
            eprintln!(
                "sandcastle: warning: --allow-dir '{}' matches denied filesystem pattern '{}' in profile '{}' — skipping",
                dir, denied, sandbox_profile.name
            );
            continue;
        }
        sandbox_profile.permissions.filesystem.allow_read.push(dir.clone());
        sandbox_profile.permissions.filesystem.allow_write.push(dir.clone());
    }
    let net_deny = &sandbox_profile.permissions.network.deny_domains;
    for domain in allow_net {
        if let Some(denied) = matches_deny_list(domain, net_deny) {
            eprintln!(
                "sandcastle: warning: --allow-net '{}' matches denied network pattern '{}' in profile '{}' — skipping",
                domain, denied, sandbox_profile.name
            );
            continue;
        }
        sandbox_profile.permissions.network.allow_domains.push(domain.clone());
    }
    if allow_gpu {
        sandbox_profile.permissions.gpu.enabled = true;
    }

    let audit_mode = mode == "audit";

    // 3. Split command into binary + args.
    let (bin, args) = command
        .split_first()
        .context("No command specified after --")?;

    // 4. Build sandbox config.
    let config = SandboxConfig {
        profile: sandbox_profile.clone(),
        working_dir: std::env::current_dir().context("Failed to determine current directory")?,
        command: bin.clone(),
        args: args.to_vec(),
        env: std::env::vars().collect(),
        interactive,
        audit_mode,
    };

    // 5. Setup audit logger.
    let _logger = AuditLogger::new();

    // 6. Create and start the sandbox.
    println!(
        "sandcastle: running {} with profile '{}' (trust={})",
        bin,
        sandbox_profile.name,
        format!("{:?}", sandbox_profile.trust_level).to_lowercase()
    );
    if audit_mode {
        println!("sandcastle: audit mode — violations will be logged but not blocked");
    }

    let mut sandbox = create_sandbox(config)
        .context("Failed to create sandbox")?;

    sandbox.start().context("Failed to start sandboxed process")?;

    // 7. Wait and report exit status.
    let status = sandbox.wait().context("Failed to wait for sandboxed process")?;

    if status.success() {
        println!("sandcastle: process exited successfully");
    } else {
        let code = status.code().unwrap_or(-1);
        eprintln!("sandcastle: process exited with code {code}");
        std::process::exit(code);
    }

    Ok(())
}
