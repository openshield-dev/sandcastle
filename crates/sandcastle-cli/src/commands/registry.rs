//! Community profile registry — search, install, and share sandbox profiles.

use anyhow::Context;
use sandcastle_policy::profile::BuiltinProfile;
use serde::{Deserialize, Serialize};

/// A single entry in the community profile registry index.
#[derive(Debug, Serialize, Deserialize)]
struct RegistryEntry {
    name: String,
    version: String,
    description: String,
    author: String,
    stars: u32,
    url: String,
    tags: Vec<String>,
}

fn entry(name: &str, desc: &str, author: &str, tags: &[&str]) -> RegistryEntry {
    RegistryEntry {
        name: name.into(),
        version: "v1.0".into(),
        description: desc.into(),
        author: author.into(),
        stars: 0,
        url: format!("builtin://{name}"),
        tags: tags.iter().map(|t| (*t).into()).collect(),
    }
}

/// Built-in registry of well-known agent profiles (no network call needed).
fn builtin_registry() -> Vec<RegistryEntry> {
    vec![
        entry("claude-code", "Anthropic Claude Code CLI agent", "anthropic", &["ai", "anthropic", "coding"]),
        entry("codex", "OpenAI Codex CLI agent", "openai", &["ai", "openai", "coding"]),
        entry("ollama", "Ollama local model server", "ollama", &["ai", "local", "gpu", "inference"]),
        entry("langchain", "LangChain agent runner framework", "langchain-ai", &["ai", "framework", "tools"]),
        entry("openclaw", "OpenClaw open-source agent framework", "openclaw", &["ai", "open-source", "agent"]),
        entry("cursor", "Cursor AI-powered editor agent", "cursor", &["ai", "editor", "coding"]),
        entry("aider", "Aider AI pair programming CLI", "paul-gauthier", &["ai", "cli", "pair-programming"]),
        entry("continue-dev", "Continue open-source autopilot for IDEs", "continue-dev", &["ai", "ide", "open-source"]),
        entry("gemini-cli", "Google Gemini CLI agent", "google", &["ai", "google", "gemini"]),
        entry("copilot-cli", "GitHub Copilot CLI agent", "github", &["ai", "github", "copilot"]),
    ]
}

/// Resolve a registry name to a `BuiltinProfile` variant.
fn resolve_builtin(name: &str) -> BuiltinProfile {
    match name {
        "claude-code" => BuiltinProfile::ClaudeCode,
        "codex" => BuiltinProfile::Codex,
        "ollama" => BuiltinProfile::Ollama,
        "langchain" => BuiltinProfile::LangChain,
        "openclaw" => BuiltinProfile::OpenClaw,
        other => BuiltinProfile::Custom(other.to_string()),
    }
}

/// Search the registry for profiles matching `query`.
///
/// Matches against name, description, and tags (case-insensitive).
pub fn search(query: &str) -> anyhow::Result<()> {
    let query_lower = query.to_lowercase();
    let registry = builtin_registry();
    let results: Vec<&RegistryEntry> = registry
        .iter()
        .filter(|e| {
            e.name.to_lowercase().contains(&query_lower)
                || e.description.to_lowercase().contains(&query_lower)
                || e.tags.iter().any(|t| t.to_lowercase().contains(&query_lower))
        })
        .collect();

    if results.is_empty() {
        println!("No profiles found matching \"{query}\".");
        return Ok(());
    }

    println!(
        "  {:<16} {:<10} {:<7} DESCRIPTION",
        "NAME", "VERSION", "STARS"
    );

    for entry in &results {
        let stars = if entry.stars == 0 {
            "-".to_string()
        } else {
            entry.stars.to_string()
        };
        println!(
            "  {:<16} {:<10} {:<7} {}",
            entry.name, entry.version, stars, entry.description,
        );
    }

    Ok(())
}

/// Install a profile by name, writing a YAML file to the current directory.
pub fn install(name: &str) -> anyhow::Result<()> {
    let registry = builtin_registry();
    let entry = registry
        .iter()
        .find(|e| e.name == name)
        .with_context(|| {
            format!("Profile '{name}' not found in registry. Use `sandcastle registry search` to browse.")
        })?;

    let builtin = resolve_builtin(&entry.name);
    let profile = builtin.to_profile();

    let file_name = format!("sandcastle.{name}.yaml");
    let path = std::env::current_dir()
        .context("Failed to determine current directory")?
        .join(&file_name);

    let yaml = serde_yaml::to_string(&profile)
        .context("Failed to serialize profile to YAML")?;

    let header = format!(
        "# SandCastle profile: {name}\n\
         # Installed from community registry ({})\n",
        entry.version,
    );

    if path.exists() {
        eprintln!("sandcastle: warning: '{}' already exists — overwriting", path.display());
    }

    std::fs::write(&path, format!("{header}{yaml}"))
        .with_context(|| format!("Failed to write '{}'", path.display()))?;

    println!("sandcastle: installed profile '{name}' -> ./{file_name}");
    Ok(())
}

/// Validate a YAML profile and print publish instructions.
pub fn publish(file: &str) -> anyhow::Result<()> {
    let contents = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read '{file}'"))?;

    // Validate that the file is parseable as a SandboxProfile.
    let _profile: sandcastle_policy::profile::SandboxProfile =
        serde_yaml::from_str(&contents)
            .with_context(|| format!("Invalid profile YAML in '{file}'"))?;

    println!("sandcastle: profile '{file}' is valid.");
    println!();
    println!("sandcastle: to publish your profile, submit a PR to:");
    println!("  https://github.com/openshield-dev/sandcastle-profiles");

    Ok(())
}
