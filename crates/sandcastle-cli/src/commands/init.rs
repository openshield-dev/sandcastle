//! Implementation of the `sandcastle init` command.
//!
//! Creates a `sandcastle.yaml` configuration file in the current directory
//! with sensible defaults based on the detected project type.

use anyhow::Context;

/// Execute the `sandcastle init` command.
pub fn execute(profile: Option<&str>) -> anyhow::Result<()> {
    let cwd = std::env::current_dir().context("Failed to determine current directory")?;
    let config_path = cwd.join("sandcastle.yaml");

    if config_path.exists() {
        anyhow::bail!(
            "sandcastle.yaml already exists in {}. Remove it first or edit it directly.",
            cwd.display()
        );
    }

    // Auto-detect project type for better defaults.
    let detected = detect_project_type(&cwd);
    let effective_profile = profile.unwrap_or_else(|| detected.default_profile());

    let yaml = generate_config(effective_profile, &detected);

    std::fs::write(&config_path, &yaml)
        .with_context(|| format!("Failed to write {}", config_path.display()))?;

    println!("sandcastle: created sandcastle.yaml");
    println!("  Profile: {effective_profile}");
    println!("  Project: {}", detected.description());
    println!();
    println!("  Next steps:");
    println!("    1. Review sandcastle.yaml and adjust permissions");
    println!("    2. Run: sandcastle run -- <your-command>");
    println!("    3. Use `sandcastle run --mode=audit` to discover what your agent needs");
    Ok(())
}

struct ProjectType {
    has_cargo: bool,
    has_package_json: bool,
    has_pyproject: bool,
    has_go_mod: bool,
}

impl ProjectType {
    fn default_profile(&self) -> &'static str {
        "develop"
    }

    fn description(&self) -> &'static str {
        if self.has_cargo {
            "Rust (Cargo)"
        } else if self.has_package_json {
            "JavaScript/TypeScript (npm)"
        } else if self.has_pyproject {
            "Python"
        } else if self.has_go_mod {
            "Go"
        } else {
            "Generic"
        }
    }

    fn extra_allow_dirs(&self) -> Vec<&'static str> {
        let mut dirs = vec!["./src", "./tests"];
        if self.has_cargo {
            dirs.push("./target");
        }
        if self.has_package_json {
            dirs.push("./node_modules");
            dirs.push("./dist");
        }
        if self.has_pyproject {
            dirs.push("./.venv");
            dirs.push("./dist");
        }
        dirs
    }

    fn extra_allow_net(&self) -> Vec<&'static str> {
        let mut domains = vec![];
        if self.has_cargo {
            domains.push("crates.io");
            domains.push("static.crates.io");
        }
        if self.has_package_json {
            domains.push("registry.npmjs.org");
        }
        if self.has_pyproject {
            domains.push("pypi.org");
            domains.push("files.pythonhosted.org");
        }
        if self.has_go_mod {
            domains.push("proxy.golang.org");
        }
        domains
    }
}

fn detect_project_type(dir: &std::path::Path) -> ProjectType {
    ProjectType {
        has_cargo: dir.join("Cargo.toml").exists(),
        has_package_json: dir.join("package.json").exists(),
        has_pyproject: dir.join("pyproject.toml").exists() || dir.join("setup.py").exists(),
        has_go_mod: dir.join("go.mod").exists(),
    }
}

fn generate_config(profile: &str, project: &ProjectType) -> String {
    let allow_dirs = project
        .extra_allow_dirs()
        .iter()
        .map(|d| format!("    - {d}"))
        .collect::<Vec<_>>()
        .join("\n");

    let allow_net = project
        .extra_allow_net()
        .iter()
        .map(|d| format!("    - {d}"))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"# SandCastle configuration
# Generated for: {desc}
# Docs: https://github.com/openshield-dev/sandcastle

profile: {profile}

filesystem:
  allow:
{allow_dirs}
  deny:
    - ~/.ssh
    - ~/.aws
    - ~/.gnupg
  overlay: true

network:
  allow:
    - api.github.com
{allow_net}
  deny_by_default: true

gpu:
  enabled: false

audit:
  path: .sandcastle/audit.jsonl

interactive: false
"#,
        desc = project.description(),
    )
}
