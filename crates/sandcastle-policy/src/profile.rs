//! Sandbox profile: a named bundle of permissions with optional overrides.

use crate::permission::{
    FsPermissions, GpuPermissions, NetworkPermissions, Permissions, ProcessPermissions,
    ResourceLimits, TrustLevel,
};
use serde::{Deserialize, Serialize};

/// A complete sandbox profile defining how a process should be isolated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxProfile {
    /// Human-readable identifier for this profile.
    pub name: String,
    /// Short description of what this profile allows.
    pub description: String,
    /// Trust level used to derive base permissions.
    pub trust_level: TrustLevel,
    /// Explicit permissions (derived from trust_level, may be further customized).
    pub permissions: Permissions,
    /// Whether audit events should be recorded for this profile.
    pub audit_enabled: bool,
}

impl Default for SandboxProfile {
    fn default() -> Self {
        let trust_level = TrustLevel::default();
        let permissions = trust_level.default_permissions();
        Self {
            name: "default".into(),
            description: "Default sandbox profile".into(),
            trust_level,
            permissions,
            audit_enabled: true,
        }
    }
}

/// Sparse override set. Only fields present here replace the corresponding
/// field in the base `TrustLevel` defaults. Deny lists are always additive.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileOverrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<FsPermissions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkPermissions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes: Option<ProcessPermissions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceLimits>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuPermissions>,
}

/// Well-known agent types that ship with built-in profiles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinProfile {
    /// Anthropic Claude Code CLI agent.
    ClaudeCode,
    /// OpenAI Codex (codex CLI).
    Codex,
    /// LangChain-based agent runners.
    LangChain,
    /// Ollama local model server.
    Ollama,
    /// OpenClaw open-source agent framework.
    OpenClaw,
    /// User-defined profile loaded from a YAML file.
    Custom(String),
}

impl BuiltinProfile {
    /// Returns the canonical name string for this profile.
    pub fn name(&self) -> &str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
            Self::LangChain => "langchain",
            Self::Ollama => "ollama",
            Self::OpenClaw => "openclaw",
            Self::Custom(name) => name,
        }
    }

    /// Returns a [`SandboxProfile`] with tuned defaults for each known agent.
    pub fn to_profile(&self) -> SandboxProfile {
        match self {
            BuiltinProfile::ClaudeCode => {
                let trust_level = TrustLevel::Develop;
                let mut permissions = trust_level.default_permissions();
                permissions.network.allow_domains.push("claude.ai".into());
                permissions
                    .network
                    .allow_domains
                    .push("*.anthropic.com".into());
                SandboxProfile {
                    name: "claude-code".into(),
                    description: "Anthropic Claude Code CLI — developer-tier isolation with Anthropic API access".into(),
                    trust_level,
                    permissions,
                    audit_enabled: true,
                }
            }

            BuiltinProfile::Codex => {
                let trust_level = TrustLevel::Develop;
                let mut permissions = trust_level.default_permissions();
                permissions
                    .network
                    .allow_domains
                    .push("api.openai.com".into());
                permissions
                    .network
                    .allow_domains
                    .push("*.openai.com".into());
                SandboxProfile {
                    name: "codex".into(),
                    description: "OpenAI Codex CLI — developer-tier isolation with OpenAI API access".into(),
                    trust_level,
                    permissions,
                    audit_enabled: true,
                }
            }

            BuiltinProfile::LangChain => {
                let trust_level = TrustLevel::Build;
                let mut permissions = trust_level.default_permissions();
                permissions
                    .network
                    .allow_domains
                    .push("*.langchain.com".into());
                permissions
                    .network
                    .allow_domains
                    .push("api.openai.com".into());
                permissions
                    .network
                    .allow_domains
                    .push("api.anthropic.com".into());
                permissions.network.allow_domains.push("serpapi.com".into());
                SandboxProfile {
                    name: "langchain".into(),
                    description: "LangChain agent runner — build-tier isolation with broad tool-calling access".into(),
                    trust_level,
                    permissions,
                    audit_enabled: true,
                }
            }

            BuiltinProfile::Ollama => {
                let trust_level = TrustLevel::Build;
                let mut permissions = trust_level.default_permissions();
                permissions.network.allow_domains =
                    vec!["ollama.ai".into(), "registry.ollama.ai".into()];
                permissions.gpu.enabled = true;
                permissions
                    .filesystem
                    .allow_read
                    .push("~/.ollama/**".into());
                permissions
                    .filesystem
                    .allow_write
                    .push("~/.ollama/**".into());
                SandboxProfile {
                    name: "ollama".into(),
                    description: "Ollama local model server — GPU-enabled, minimal network, local model store".into(),
                    trust_level,
                    permissions,
                    audit_enabled: true,
                }
            }

            BuiltinProfile::OpenClaw => {
                let trust_level = TrustLevel::Develop;
                let mut permissions = trust_level.default_permissions();
                permissions
                    .network
                    .allow_domains
                    .push("*.openclaw.ai".into());
                SandboxProfile {
                    name: "openclaw".into(),
                    description: "OpenClaw open-source agent — developer-tier isolation".into(),
                    trust_level,
                    permissions,
                    audit_enabled: true,
                }
            }

            BuiltinProfile::Custom(name) => {
                let trust_level = TrustLevel::Develop;
                let permissions = trust_level.default_permissions();
                SandboxProfile {
                    name: name.clone(),
                    description: format!(
                        "Custom profile '{}' — developer-tier defaults, apply overrides as needed",
                        name
                    ),
                    trust_level,
                    permissions,
                    audit_enabled: true,
                }
            }
        }
    }
}

impl SandboxProfile {
    /// Create a maximally restrictive sandbox profile (Explore trust level).
    pub fn isolated(name: impl Into<String>) -> Self {
        let trust_level = TrustLevel::Explore;
        let permissions = trust_level.default_permissions();
        Self {
            name: name.into(),
            description: "Maximum isolation — read-only project access, no network".into(),
            trust_level,
            permissions,
            audit_enabled: true,
        }
    }

    /// Create a profile with local working directory access and allowlisted network.
    pub fn local_work(name: impl Into<String>) -> Self {
        let trust_level = TrustLevel::Develop;
        let permissions = trust_level.default_permissions();
        Self {
            name: name.into(),
            description: "Working directory read/write, allowlisted network access".into(),
            trust_level,
            permissions,
            audit_enabled: true,
        }
    }
}
