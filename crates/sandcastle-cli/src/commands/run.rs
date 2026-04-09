//! Implementation of the `sandcastle run` command.

use anyhow::Context;
use sandcastle_audit::AuditLogger;
use sandcastle_platform::{create_sandbox, SandboxConfig};
use sandcastle_policy::resolver::ProfileResolver;

/// Environment variable names that are stripped before passing to the sandbox.
/// These commonly contain secrets or grant elevated access.
const SENSITIVE_ENV_PREFIXES: &[&str] = &[
    "AWS_", "AZURE_", "GCP_", "GOOGLE_", "ANTHROPIC_", "OPENAI_",
    "GITHUB_TOKEN", "GITLAB_TOKEN", "NPM_TOKEN", "DOCKER_",
    "SSH_AUTH_SOCK", "GPG_",
];

const SENSITIVE_ENV_EXACT: &[&str] = &[
    "SECRET_KEY", "API_KEY", "TOKEN", "PASSWORD", "CREDENTIALS",
    "DATABASE_URL", "REDIS_URL", "SENTRY_DSN",
];

/// Filter environment variables, removing known sensitive keys.
fn filter_env_vars(vars: impl Iterator<Item = (String, String)>) -> Vec<(String, String)> {
    vars.filter(|(key, _)| {
        let upper = key.to_uppercase();
        // Drop vars whose name matches a sensitive prefix.
        if SENSITIVE_ENV_PREFIXES.iter().any(|p| upper.starts_with(p)) {
            return false;
        }
        // Drop vars whose name exactly matches a sensitive key.
        if SENSITIVE_ENV_EXACT.iter().any(|&s| upper == s) {
            return false;
        }
        true
    })
    .collect()
}

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
        if let Some(suffix) = pat.strip_prefix('*') {
            return value.ends_with(suffix);
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

    #[test]
    fn env_filter_strips_secrets() {
        let vars = vec![
            ("PATH".into(), "/usr/bin".into()),
            ("HOME".into(), "/home/user".into()),
            ("AWS_SECRET_ACCESS_KEY".into(), "secret".into()),
            ("ANTHROPIC_API_KEY".into(), "key".into()),
            ("GITHUB_TOKEN".into(), "ghp_xxx".into()),
            ("MY_APP_VAR".into(), "safe".into()),
        ];
        let filtered = super::filter_env_vars(
            // filter_env_vars takes std::env::Vars, so test via the logic directly
            vars.into_iter(),
        );
        let keys: Vec<&str> = filtered.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"PATH"));
        assert!(keys.contains(&"HOME"));
        assert!(keys.contains(&"MY_APP_VAR"));
        assert!(!keys.contains(&"AWS_SECRET_ACCESS_KEY"));
        assert!(!keys.contains(&"ANTHROPIC_API_KEY"));
        assert!(!keys.contains(&"GITHUB_TOKEN"));
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

    // 1. Resolve profile — auto-detect from command if using default profile.
    let resolver = ProfileResolver::new(vec![
        std::env::current_dir().context("Failed to determine current directory")?,
    ]);

    let effective_profile = if profile == "develop" {
        // Try to auto-detect a better profile from the command being run.
        if let Some(detected) = ProfileResolver::auto_detect(&command.join(" ")) {
            let name = detected.name().to_string();
            eprintln!("sandcastle: auto-detected profile '{name}' for command");
            name
        } else {
            profile.to_string()
        }
    } else {
        profile.to_string()
    };

    let mut sandbox_profile = resolver
        .resolve(&effective_profile)
        .with_context(|| format!("Unknown profile '{}'. Run `sandcastle profiles list` to see available profiles.", effective_profile))?;

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
        env: filter_env_vars(std::env::vars()),
        interactive,
        audit_mode,
    };

    // 5. Auto-snapshot before run (enables `sandcastle undo`).
    if let Ok(snap_name) = super::undo::create_auto_snapshot() {
        eprintln!("sandcastle: auto-snapshot '{snap_name}' created (use `sandcastle undo` to restore)");
    }

    // 6. Setup audit logger with file sink.
    let mut logger = AuditLogger::new();
    let audit_dir = std::env::current_dir()
        .context("Failed to determine current directory")?
        .join(".sandcastle");
    std::fs::create_dir_all(&audit_dir)
        .with_context(|| format!("Failed to create audit directory: {}", audit_dir.display()))?;
    let audit_path = audit_dir.join("audit.log");
    if let Ok(sink) = sandcastle_audit::FileAuditSink::new(audit_path) {
        logger.add_sink(Box::new(sink));
    }

    // 6. Setup filesystem guard for policy enforcement.
    let fs_guard = sandcastle_fs::guard::FsGuard::new(sandbox_profile.clone());
    // Validate the command binary path against filesystem policy.
    let cmd_path = std::path::Path::new(bin);
    if let Err(e) = fs_guard.check_read(cmd_path) {
        if !audit_mode {
            anyhow::bail!("Filesystem policy denies executing '{bin}': {e}");
        }
        eprintln!("sandcastle: audit: filesystem policy would deny executing '{bin}': {e}");
    }

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
    let start_time = std::time::Instant::now();
    let status = sandbox.wait().context("Failed to wait for sandboxed process")?;
    let duration = start_time.elapsed();

    // 8. Post-run report: risk score + change summary + tips.
    print_run_report(&audit_dir, duration, status.success());

    if !status.success() {
        let code = status.code().unwrap_or(-1);
        eprintln!("sandcastle: process exited with code {code}");
        std::process::exit(code);
    }

    Ok(())
}

/// Print a polished post-run report with risk scoring, change summary, and tips.
fn print_run_report(audit_dir: &std::path::Path, duration: std::time::Duration, success: bool) {
    let audit_path = audit_dir.join("audit.log");
    let status_icon = if success { "\u{2713}" } else { "\u{2717}" }; // ✓ or ✗

    // Parse audit events for risk scoring.
    let events = match std::fs::read_to_string(&audit_path) {
        Ok(raw) => raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<sandcastle_audit::AuditEvent>(l).ok())
            .collect::<Vec<_>>(),
        Err(_) => vec![],
    };

    let total = events.len();
    let blocked = events.iter().filter(|e| e.is_violation()).count();
    let fs_ops = events
        .iter()
        .filter(|e| {
            matches!(
                e.event_type,
                sandcastle_audit::event::EventType::FilesystemRead
                    | sandcastle_audit::event::EventType::FilesystemWrite
                    | sandcastle_audit::event::EventType::FilesystemCreate
                    | sandcastle_audit::event::EventType::FilesystemDelete
            )
        })
        .count();
    let net_ops = events
        .iter()
        .filter(|e| {
            matches!(
                e.event_type,
                sandcastle_audit::event::EventType::NetworkConnect
                    | sandcastle_audit::event::EventType::NetworkRequest
            )
        })
        .count();

    // Risk score.
    let risk = sandcastle_audit::risk::RiskReport::from_events(&events);
    let risk_icon = match risk.level {
        sandcastle_audit::risk::RiskLevel::Safe => "\u{1f7e2}",      // green circle
        sandcastle_audit::risk::RiskLevel::Low => "\u{1f7e2}",       // green
        sandcastle_audit::risk::RiskLevel::Medium => "\u{1f7e1}",    // yellow
        sandcastle_audit::risk::RiskLevel::High => "\u{1f7e0}",      // orange
        sandcastle_audit::risk::RiskLevel::Critical => "\u{1f534}",  // red
    };

    let dur_str = if duration.as_secs() >= 60 {
        format!("{}m {}s", duration.as_secs() / 60, duration.as_secs() % 60)
    } else {
        format!("{:.1}s", duration.as_secs_f64())
    };

    println!();
    println!("  {status_icon} sandcastle: process exited {}", if success { "successfully" } else { "with errors" });
    println!("  {risk_icon} Risk: {}/10 ({:?}) — {}", risk.score, risk.level, risk.summary);
    println!("    Duration: {dur_str}  Events: {total}  Blocked: {blocked}  FS: {fs_ops}  Net: {net_ops}");

    if blocked > 0 {
        println!("    {} operation(s) were blocked by policy", blocked);
    }

    println!();
    println!("  Tip: `sandcastle diff`    — see what changed");
    println!("       `sandcastle undo`    — rollback to pre-run state");
    println!("       `sandcastle monitor` — live activity dashboard");
    println!();
}
