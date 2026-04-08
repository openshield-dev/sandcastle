//! Implementation of the `sandcastle profiles` subcommands.

use anyhow::Context;
use sandcastle_policy::profile::BuiltinProfile;
use sandcastle_policy::resolver::ProfileResolver;

/// All built-in profiles with their display names and descriptions.
static BUILTINS: &[(&str, BuiltinProfile)] = &[
    ("claude-code", BuiltinProfile::ClaudeCode),
    ("codex", BuiltinProfile::Codex),
    ("langchain", BuiltinProfile::LangChain),
    ("ollama", BuiltinProfile::Ollama),
    ("openclaw", BuiltinProfile::OpenClaw),
];

/// List all built-in profiles with their trust levels.
pub fn list() -> anyhow::Result<()> {
    println!("{:<16} {:<14} {}", "NAME", "TRUST LEVEL", "DESCRIPTION");
    println!("{}", "-".repeat(80));

    for (name, builtin) in BUILTINS {
        let profile = builtin.to_profile();
        println!(
            "{:<16} {:<14} {}",
            name,
            format!("{:?}", profile.trust_level).to_lowercase(),
            profile.description,
        );
    }

    println!();
    println!("Use `sandcastle profiles show <name>` for full permission details.");
    println!("Use `sandcastle profiles create <name>` to scaffold a custom profile YAML.");
    Ok(())
}

/// Show detailed information about a named profile.
pub fn show(name: &str) -> anyhow::Result<()> {
    let resolver = ProfileResolver::new(vec![
        std::env::current_dir().context("Failed to determine current directory")?,
    ]);

    let p = resolver
        .resolve(name)
        .with_context(|| format!("Profile '{name}' not found. Run `sandcastle profiles list` to see available profiles."))?;

    println!("Profile: {}", p.name);
    println!("  description : {}", p.description);
    println!("  trust_level : {:?}", p.trust_level);
    println!("  audit       : {}", p.audit_enabled);
    println!("  gpu         : {}", p.permissions.gpu.enabled);
    println!();

    println!("Filesystem read:");
    for path in &p.permissions.filesystem.allow_read {
        println!("  + {path}");
    }
    println!("Filesystem write:");
    for path in &p.permissions.filesystem.allow_write {
        println!("  + {path}");
    }
    println!("Filesystem deny:");
    for path in &p.permissions.filesystem.deny {
        println!("  - {path}");
    }
    println!();

    println!("Network allow:");
    for domain in &p.permissions.network.allow_domains {
        println!("  + {domain}");
    }
    println!("Network deny:");
    for domain in &p.permissions.network.deny_domains {
        println!("  - {domain}");
    }
    if let Some(bw) = &p.permissions.network.max_bandwidth {
        println!("  bandwidth cap: {bw}");
    }
    println!();

    println!("Processes allow:");
    for proc in &p.permissions.processes.allow {
        println!("  + {proc}");
    }
    println!("Processes deny:");
    for proc in &p.permissions.processes.deny {
        println!("  - {proc}");
    }
    println!();

    println!("Resource limits:");
    if let Some(cpu) = &p.permissions.resources.max_cpu {
        println!("  cpu          : {cpu}");
    }
    if let Some(mem) = &p.permissions.resources.max_memory {
        println!("  memory       : {mem}");
    }
    if let Some(disk) = &p.permissions.resources.max_disk {
        println!("  disk         : {disk}");
    }
    if let Some(fds) = p.permissions.resources.max_open_files {
        println!("  open_files   : {fds}");
    }

    Ok(())
}

/// Scaffold a new custom profile YAML in the current directory.
pub fn create(name: &str) -> anyhow::Result<()> {
    super::validate::validate_name(name)?;

    let file_name = format!("sandcastle.{name}.yaml");
    let path = std::env::current_dir()
        .context("Failed to determine current directory")?
        .join(&file_name);

    anyhow::ensure!(
        !path.exists(),
        "Profile file '{}' already exists.",
        path.display()
    );

    // Build the profile structure programmatically and serialize via serde_yaml
    // to avoid YAML injection through the name field.
    let yaml = serde_yaml::to_string(&serde_yaml::Value::Mapping({
        let mut m = serde_yaml::Mapping::new();
        m.insert("name".into(), name.into());
        m.insert("description".into(), "Custom profile — adjust permissions as needed".into());
        m.insert("trust_level".into(), "develop".into());
        m.insert("audit_enabled".into(), serde_yaml::Value::Bool(true));

        let mut perms = serde_yaml::Mapping::new();

        // filesystem
        let mut fs = serde_yaml::Mapping::new();
        fs.insert("allow_read".into(), serde_yaml::Value::Sequence(vec![
            "$PROJECT_DIR/**".into(), "~/**".into(),
        ]));
        fs.insert("allow_write".into(), serde_yaml::Value::Sequence(vec![
            "$PROJECT_DIR/**".into(),
        ]));
        fs.insert("deny".into(), serde_yaml::Value::Sequence(vec![
            "/etc/**".into(), "/sys/**".into(), "/proc/**".into(),
            "~/.ssh/**".into(), "~/.gnupg/**".into(), "~/.aws/**".into(),
        ]));
        perms.insert("filesystem".into(), serde_yaml::Value::Mapping(fs));

        // network
        let mut net = serde_yaml::Mapping::new();
        net.insert("allow_domains".into(), serde_yaml::Value::Sequence(vec![
            "github.com".into(), "*.github.com".into(),
        ]));
        net.insert("deny_domains".into(), serde_yaml::Value::Sequence(vec![]));
        perms.insert("network".into(), serde_yaml::Value::Mapping(net));

        // processes
        let mut proc_m = serde_yaml::Mapping::new();
        proc_m.insert("allow".into(), serde_yaml::Value::Sequence(vec![
            "git".into(),
        ]));
        proc_m.insert("deny".into(), serde_yaml::Value::Sequence(vec![
            "sudo".into(), "su".into(),
        ]));
        perms.insert("processes".into(), serde_yaml::Value::Mapping(proc_m));

        // resources
        let mut res = serde_yaml::Mapping::new();
        res.insert("max_cpu".into(), "100%".into());
        res.insert("max_memory".into(), "4GB".into());
        res.insert("max_disk".into(), "10GB".into());
        res.insert("max_open_files".into(), serde_yaml::Value::Number(1024.into()));
        perms.insert("resources".into(), serde_yaml::Value::Mapping(res));

        // gpu
        let mut gpu = serde_yaml::Mapping::new();
        gpu.insert("enabled".into(), serde_yaml::Value::Bool(false));
        gpu.insert("devices".into(), serde_yaml::Value::Sequence(vec![]));
        perms.insert("gpu".into(), serde_yaml::Value::Mapping(gpu));

        m.insert("permissions".into(), serde_yaml::Value::Mapping(perms));
        m
    }))
    .context("Failed to serialize profile YAML")?;

    let header = format!(
        "# SandCastle profile: {name}\n\
         # Generated by `sandcastle profiles create {name}`\n\
         # Trust levels: explore | develop | build | full | unrestricted\n"
    );

    std::fs::write(&path, format!("{header}{yaml}"))
        .with_context(|| format!("Failed to write '{}'", path.display()))?;

    println!("Created '{}'", path.display());
    println!("Edit the file, then validate it with:");
    println!("  sandcastle policy validate {file_name}");
    println!("Run with:");
    println!("  sandcastle run --profile {name} -- <command>");

    Ok(())
}
