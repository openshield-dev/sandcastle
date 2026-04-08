//! Implementation of the `sandcastle policy` subcommands.

use anyhow::Context;
use sandcastle_policy::resolver::ProfileResolver;

/// Generate a policy YAML skeleton from an audit log file.
///
/// In future milestones this will parse the NDJSON audit log and produce a
/// minimal-privilege policy that permits exactly what was observed.
pub fn generate(from_audit: &str) -> anyhow::Result<()> {
    let path = std::path::Path::new(from_audit);
    anyhow::ensure!(path.exists(), "Audit log file not found: {from_audit}");

    println!("sandcastle policy generate: reading audit log '{from_audit}'");
    println!();
    println!("# Generated sandcastle.yaml");
    println!("# (policy generation from audit logs is a planned feature)");
    println!("#");
    println!("# Review the audit log manually and create a profile YAML such as:");
    println!("# name: my-agent");
    println!("# description: Auto-generated from audit log");
    println!("# trust_level: develop");
    println!("# permissions:");
    println!("#   filesystem:");
    println!("#     allow_read: [\"$PROJECT_DIR/**\"]");
    println!("#     allow_write: [\"$PROJECT_DIR/**\"]");
    println!("#     deny: []");
    println!("#   network:");
    println!("#     allow_domains: []");
    println!("#     deny_domains: []");
    Ok(())
}

/// Validate a profile YAML file, printing a success message or the parse error.
pub fn validate(file: &str) -> anyhow::Result<()> {
    let path = std::path::Path::new(file);
    anyhow::ensure!(path.exists(), "Profile file not found: {file}");

    let profile = ProfileResolver::load_from_file(path)
        .with_context(|| format!("Failed to parse profile '{file}'"))?;

    println!("Profile '{}' is valid.", profile.name);
    println!("  description : {}", profile.description);
    println!("  trust_level : {:?}", profile.trust_level);
    println!("  audit       : {}", profile.audit_enabled);
    Ok(())
}

/// Resolve and pretty-print the effective permissions for a named profile.
pub fn show(profile: &str) -> anyhow::Result<()> {
    let resolver = ProfileResolver::new(vec![
        std::env::current_dir().context("Failed to determine current directory")?,
    ]);

    let p = resolver
        .resolve(profile)
        .with_context(|| format!("Profile '{profile}' not found"))?;

    println!("Profile: {}", p.name);
    println!("  description : {}", p.description);
    println!("  trust_level : {:?}", p.trust_level);
    println!("  audit       : {}", p.audit_enabled);
    println!();

    let fs = &p.permissions.filesystem;
    println!("Filesystem:");
    print_list("  allow_read", &fs.allow_read);
    print_list("  allow_write", &fs.allow_write);
    print_list("  deny", &fs.deny);

    let net = &p.permissions.network;
    println!("\nNetwork:");
    print_list("  allow_domains", &net.allow_domains);
    print_list("  deny_domains", &net.deny_domains);
    if let Some(bw) = &net.max_bandwidth {
        println!("  max_bandwidth : {bw}");
    }

    let proc = &p.permissions.processes;
    println!("\nProcesses:");
    print_list("  allow", &proc.allow);
    print_list("  deny", &proc.deny);

    let res = &p.permissions.resources;
    println!("\nResources:");
    if let Some(cpu) = &res.max_cpu {
        println!("  max_cpu        : {cpu}");
    }
    if let Some(mem) = &res.max_memory {
        println!("  max_memory     : {mem}");
    }
    if let Some(disk) = &res.max_disk {
        println!("  max_disk       : {disk}");
    }
    if let Some(fds) = res.max_open_files {
        println!("  max_open_files : {fds}");
    }

    let gpu = &p.permissions.gpu;
    println!("\nGPU:");
    println!("  enabled : {}", gpu.enabled);
    if !gpu.devices.is_empty() {
        print_list("  devices", &gpu.devices);
    }

    Ok(())
}

fn print_list(label: &str, items: &[String]) {
    if items.is_empty() {
        println!("{label} : (none)");
    } else {
        println!("{label}:");
        for item in items {
            println!("    - {item}");
        }
    }
}
