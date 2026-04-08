//! Fine-grained permission types that make up a sandbox policy.

use serde::{Deserialize, Serialize};

/// Trust levels for sandbox profiles, ordered from most restrictive to least.
///
/// Ordering: Explore < Develop < Build < Full < Unrestricted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Read-only access to the project directory. No network, no process execution.
    Explore,
    /// Project directory read/write, home read-only, allowlisted domains. No shell. Default.
    #[default]
    Develop,
    /// Project + dep dirs r/w, package registries + API endpoints, build tools, GPU.
    Build,
    /// Most dirs r/w (deny system paths), most domains, most processes (audit-logged), GPU.
    Full,
    /// Everything allowed. Use only in fully isolated, ephemeral environments.
    Unrestricted,
}

impl TrustLevel {
    /// Returns sensible default [`Permissions`] for this trust level.
    pub fn default_permissions(&self) -> Permissions {
        match self {
            TrustLevel::Explore => Permissions {
                filesystem: FsPermissions {
                    allow_read: vec!["$PROJECT_DIR/**".into()],
                    allow_write: vec![],
                    deny: vec![
                        "/etc/**".into(),
                        "/sys/**".into(),
                        "/proc/**".into(),
                        "~/.ssh/**".into(),
                        "~/.gnupg/**".into(),
                    ],
                },
                network: NetworkPermissions {
                    allow_domains: vec![],
                    deny_domains: vec!["*".into()],
                    max_bandwidth: None,
                },
                processes: ProcessPermissions {
                    allow: vec![],
                    deny: vec!["*".into()],
                },
                resources: ResourceLimits {
                    max_cpu: Some("50%".into()),
                    max_memory: Some("512MB".into()),
                    max_disk: None,
                    max_open_files: Some(256),
                },
                gpu: GpuPermissions {
                    enabled: false,
                    devices: vec![],
                },
            },

            TrustLevel::Develop => Permissions {
                filesystem: FsPermissions {
                    allow_read: vec!["$PROJECT_DIR/**".into(), "~/**".into()],
                    allow_write: vec!["$PROJECT_DIR/**".into()],
                    deny: vec![
                        "/etc/**".into(),
                        "/sys/**".into(),
                        "/proc/**".into(),
                        "~/.ssh/**".into(),
                        "~/.gnupg/**".into(),
                        "~/.aws/**".into(),
                        "~/.config/gcloud/**".into(),
                    ],
                },
                network: NetworkPermissions {
                    allow_domains: vec![
                        "github.com".into(),
                        "*.github.com".into(),
                        "api.anthropic.com".into(),
                        "api.openai.com".into(),
                        "crates.io".into(),
                        "npmjs.com".into(),
                        "*.npmjs.com".into(),
                        "pypi.org".into(),
                        "*.pypi.org".into(),
                    ],
                    deny_domains: vec![
                        "169.254.169.254".into(), // AWS/GCP metadata
                        "metadata.google.internal".into(), // GCP metadata
                        "metadata.internal".into(),
                    ],
                    max_bandwidth: Some("50Mbps".into()),
                },
                processes: ProcessPermissions {
                    allow: vec![
                        "git".into(),
                        "cargo".into(),
                        "npm".into(),
                        "npx".into(),
                        "node".into(),
                        "python".into(),
                        "python3".into(),
                        "pip".into(),
                        "pip3".into(),
                        "rustc".into(),
                        "rustfmt".into(),
                        "clippy-driver".into(),
                    ],
                    deny: vec![
                        "sh".into(),
                        "bash".into(),
                        "zsh".into(),
                        "fish".into(),
                        "sudo".into(),
                        "su".into(),
                        "chmod".into(),
                        "chown".into(),
                        "curl".into(),
                        "wget".into(),
                    ],
                },
                resources: ResourceLimits {
                    max_cpu: Some("100%".into()),
                    max_memory: Some("4GB".into()),
                    max_disk: Some("10GB".into()),
                    max_open_files: Some(1024),
                },
                gpu: GpuPermissions {
                    enabled: false,
                    devices: vec![],
                },
            },

            TrustLevel::Build => Permissions {
                filesystem: FsPermissions {
                    allow_read: vec![
                        "$PROJECT_DIR/**".into(),
                        "~/.cargo/**".into(),
                        "~/.npm/**".into(),
                        "~/.cache/**".into(),
                        "/usr/local/**".into(),
                        "/usr/lib/**".into(),
                        "/usr/include/**".into(),
                    ],
                    allow_write: vec![
                        "$PROJECT_DIR/**".into(),
                        "~/.cargo/**".into(),
                        "~/.npm/**".into(),
                        "~/.cache/**".into(),
                        "/tmp/**".into(),
                    ],
                    deny: vec![
                        "/etc/passwd".into(),
                        "/etc/shadow".into(),
                        "/etc/sudoers".into(),
                        "~/.ssh/**".into(),
                        "~/.gnupg/**".into(),
                        "~/.aws/**".into(),
                    ],
                },
                network: NetworkPermissions {
                    allow_domains: vec![
                        "github.com".into(),
                        "*.github.com".into(),
                        "*.githubusercontent.com".into(),
                        "api.anthropic.com".into(),
                        "api.openai.com".into(),
                        "crates.io".into(),
                        "static.crates.io".into(),
                        "npmjs.com".into(),
                        "*.npmjs.com".into(),
                        "registry.npmjs.org".into(),
                        "pypi.org".into(),
                        "*.pypi.org".into(),
                        "files.pythonhosted.org".into(),
                        "pkg.go.dev".into(),
                        "sum.golang.org".into(),
                        "hub.docker.com".into(),
                        "registry-1.docker.io".into(),
                    ],
                    deny_domains: vec![
                        "169.254.169.254".into(), // AWS/GCP metadata
                        "metadata.google.internal".into(), // GCP metadata
                        "metadata.internal".into(),
                    ],
                    max_bandwidth: Some("200Mbps".into()),
                },
                processes: ProcessPermissions {
                    allow: vec![
                        "git".into(),
                        "cargo".into(),
                        "rustc".into(),
                        "rustfmt".into(),
                        "clippy-driver".into(),
                        "npm".into(),
                        "npx".into(),
                        "node".into(),
                        "python".into(),
                        "python3".into(),
                        "pip".into(),
                        "pip3".into(),
                        "make".into(),
                        "cmake".into(),
                        "gcc".into(),
                        "clang".into(),
                        "ld".into(),
                        "ar".into(),
                        "docker".into(),
                        "sh".into(),
                        "bash".into(),
                    ],
                    deny: vec!["sudo".into(), "su".into(), "passwd".into()],
                },
                resources: ResourceLimits {
                    max_cpu: Some("200%".into()),
                    max_memory: Some("8GB".into()),
                    max_disk: Some("50GB".into()),
                    max_open_files: Some(4096),
                },
                gpu: GpuPermissions {
                    enabled: true,
                    devices: vec![],
                },
            },

            TrustLevel::Full => Permissions {
                filesystem: FsPermissions {
                    allow_read: vec!["/**".into(), "~/**".into()],
                    allow_write: vec!["/**".into(), "~/**".into()],
                    deny: vec![
                        "/etc/shadow".into(),
                        "/etc/sudoers".into(),
                        "/proc/sysrq-trigger".into(),
                        "/sys/firmware/**".into(),
                        "/sys/kernel/**".into(),
                    ],
                },
                network: NetworkPermissions {
                    allow_domains: vec!["*".into()],
                    deny_domains: vec![
                        "169.254.169.254".into(), // cloud metadata
                        "metadata.google.internal".into(),
                        "metadata.internal".into(),
                    ],
                    max_bandwidth: None,
                },
                processes: ProcessPermissions {
                    allow: vec!["*".into()],
                    deny: vec![
                        "sudo".into(),
                        "su".into(),
                        "passwd".into(),
                        "visudo".into(),
                    ],
                },
                resources: ResourceLimits {
                    max_cpu: None,
                    max_memory: None,
                    max_disk: None,
                    max_open_files: None,
                },
                gpu: GpuPermissions {
                    enabled: true,
                    devices: vec![],
                },
            },

            TrustLevel::Unrestricted => Permissions {
                filesystem: FsPermissions {
                    allow_read: vec!["*".into()],
                    allow_write: vec!["*".into()],
                    deny: vec![],
                },
                network: NetworkPermissions {
                    allow_domains: vec!["*".into()],
                    deny_domains: vec![],
                    max_bandwidth: None,
                },
                processes: ProcessPermissions {
                    allow: vec!["*".into()],
                    deny: vec![],
                },
                resources: ResourceLimits {
                    max_cpu: None,
                    max_memory: None,
                    max_disk: None,
                    max_open_files: None,
                },
                gpu: GpuPermissions {
                    enabled: true,
                    devices: vec![],
                },
            },
        }
    }
}

/// Controls what filesystem paths an agent may access.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FsPermissions {
    /// Glob patterns the agent is allowed to read.
    pub allow_read: Vec<String>,
    /// Glob patterns the agent is allowed to write.
    pub allow_write: Vec<String>,
    /// Glob patterns that are always denied regardless of allow rules.
    pub deny: Vec<String>,
}

/// Controls outbound network access.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkPermissions {
    /// Domains (or wildcards) the agent may connect to.
    pub allow_domains: Vec<String>,
    /// Domains that are always blocked.
    pub deny_domains: Vec<String>,
    /// Optional bandwidth cap as a human-readable string (e.g. "10Mbps").
    pub max_bandwidth: Option<String>,
}

/// Controls which external processes the agent may spawn.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessPermissions {
    /// Command names or glob patterns the agent is allowed to execute.
    pub allow: Vec<String>,
    /// Command names or glob patterns that are always blocked.
    pub deny: Vec<String>,
}

/// Hard resource caps applied to the sandbox.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum CPU quota as a human-readable string (e.g. "200%").
    pub max_cpu: Option<String>,
    /// Maximum resident memory (e.g. "4GB").
    pub max_memory: Option<String>,
    /// Maximum disk usage (e.g. "20GB").
    pub max_disk: Option<String>,
    /// Maximum number of open file descriptors.
    pub max_open_files: Option<u64>,
}

/// Controls GPU device access.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GpuPermissions {
    /// Whether the agent may access GPU devices at all.
    pub enabled: bool,
    /// Specific device identifiers to expose (empty = all available).
    pub devices: Vec<String>,
}

/// Aggregated permission set governing every isolation axis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Permissions {
    pub filesystem: FsPermissions,
    pub network: NetworkPermissions,
    pub processes: ProcessPermissions,
    pub resources: ResourceLimits,
    pub gpu: GpuPermissions,
}

impl Permissions {
    /// Merges base permissions with a set of overrides from a [`ProfileOverrides`].
    ///
    /// When an override field is `Some`, it replaces the corresponding base field for
    /// allow lists while **extending** deny lists (deny lists are always additive —
    /// once denied, a subject stays denied regardless of the allow side).
    pub fn merge(&self, overrides: &crate::profile::ProfileOverrides) -> Permissions {
        let filesystem = if let Some(fs) = &overrides.filesystem {
            // Allow lists from the override win; deny lists accumulate.
            let mut deny = self.filesystem.deny.clone();
            for d in &fs.deny {
                if !deny.contains(d) {
                    deny.push(d.clone());
                }
            }
            FsPermissions {
                allow_read: fs.allow_read.clone(),
                allow_write: fs.allow_write.clone(),
                deny,
            }
        } else {
            self.filesystem.clone()
        };

        let network = if let Some(net) = &overrides.network {
            let mut deny_domains = self.network.deny_domains.clone();
            for d in &net.deny_domains {
                if !deny_domains.contains(d) {
                    deny_domains.push(d.clone());
                }
            }
            NetworkPermissions {
                allow_domains: net.allow_domains.clone(),
                deny_domains,
                max_bandwidth: net.max_bandwidth.clone().or(self.network.max_bandwidth.clone()),
            }
        } else {
            self.network.clone()
        };

        let processes = if let Some(proc) = &overrides.processes {
            let mut deny = self.processes.deny.clone();
            for d in &proc.deny {
                if !deny.contains(d) {
                    deny.push(d.clone());
                }
            }
            ProcessPermissions {
                allow: proc.allow.clone(),
                deny,
            }
        } else {
            self.processes.clone()
        };

        let resources = overrides
            .resources
            .clone()
            .unwrap_or_else(|| self.resources.clone());

        let gpu = overrides
            .gpu
            .clone()
            .unwrap_or_else(|| self.gpu.clone());

        Permissions {
            filesystem,
            network,
            processes,
            resources,
            gpu,
        }
    }
}
