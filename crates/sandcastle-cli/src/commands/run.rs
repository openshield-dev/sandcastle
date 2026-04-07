//! Implementation of the `sandcastle run` command.

use anyhow::Context;
use sandcastle_audit::AuditLogger;
use sandcastle_platform::{create_sandbox, SandboxConfig};
use sandcastle_policy::resolver::ProfileResolver;

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
    // 1. Resolve profile using the policy resolver.
    let resolver = ProfileResolver::new(vec![
        std::env::current_dir().unwrap_or_default(),
    ]);

    let mut sandbox_profile = resolver
        .resolve(profile)
        .with_context(|| format!("Unknown profile '{}'. Run `sandcastle profiles list` to see available profiles.", profile))?;

    // 2. Apply CLI overrides.
    for dir in allow_dirs {
        sandbox_profile.permissions.filesystem.allow_read.push(dir.clone());
        sandbox_profile.permissions.filesystem.allow_write.push(dir.clone());
    }
    for domain in allow_net {
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
        working_dir: std::env::current_dir().unwrap_or_default(),
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
