//! Filter generator — compiles a [`Permissions`] set to platform-specific isolation rules.
//!
//! Actual BPF bytecode, Landlock ruleset construction, and macOS sandbox profile
//! serialization live in `sandcastle-platform`. This module produces an abstract
//! [`GeneratedFilter`] that the platform crate translates into OS primitives.

use serde::{Deserialize, Serialize};

use crate::error::PolicyError;
use crate::permission::Permissions;

/// The platform target that a generated filter is destined for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterTarget {
    /// Linux seccomp BPF syscall filter.
    SeccompBpf,
    /// Linux Landlock LSM ruleset.
    LandlockRuleset,
    /// macOS sandbox(7) profile (Scheme-like DSL).
    MacOsSandboxProfile,
    /// Windows Job Object constraints.
    WindowsJobObject,
    /// Windows AppContainer (Low Integrity Level).
    WindowsAppContainer,
}

/// The action a filter rule takes when its subject matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterAction {
    /// Permit the operation.
    Allow,
    /// Block the operation (returns an error to the caller).
    Deny,
    /// Permit the operation but emit an audit log entry.
    Log,
}

/// A single abstract isolation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterRule {
    /// What the sandbox should do when this rule matches.
    pub action: FilterAction,
    /// The resource category this rule applies to (e.g. "filesystem", "network").
    pub subject: String,
    /// Human-readable detail that the platform crate translates to native syntax.
    pub detail: String,
}

/// The complete set of abstract rules for one sandbox invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedFilter {
    /// The platform this filter is destined for.
    pub target: FilterTarget,
    /// Ordered list of rules (evaluated top-to-bottom; first match wins).
    pub rules: Vec<FilterRule>,
}

/// Compiles [`Permissions`] into abstract [`GeneratedFilter`] values.
pub struct FilterGenerator;

impl FilterGenerator {
    /// Generate a [`GeneratedFilter`] for the given permissions and target platform.
    ///
    /// Rules are ordered deny-first so that the platform crate's first-match
    /// semantics correctly enforce deny lists before allow lists.
    pub fn generate(
        permissions: &Permissions,
        target: FilterTarget,
    ) -> Result<GeneratedFilter, PolicyError> {
        let mut rules: Vec<FilterRule> = Vec::new();

        // --- Filesystem rules -----------------------------------------------
        // Deny entries are unconditional and must come first.
        for path in &permissions.filesystem.deny {
            rules.push(FilterRule {
                action: FilterAction::Deny,
                subject: "filesystem".into(),
                detail: format!("deny path={}", path),
            });
        }
        for path in &permissions.filesystem.allow_read {
            rules.push(FilterRule {
                action: FilterAction::Allow,
                subject: "filesystem".into(),
                detail: format!("allow read path={}", path),
            });
        }
        for path in &permissions.filesystem.allow_write {
            rules.push(FilterRule {
                action: FilterAction::Allow,
                subject: "filesystem".into(),
                detail: format!("allow write path={}", path),
            });
        }
        // Default-deny anything not explicitly allowed.
        rules.push(FilterRule {
            action: FilterAction::Deny,
            subject: "filesystem".into(),
            detail: "deny path=*".into(),
        });

        // --- Network rules --------------------------------------------------
        for domain in &permissions.network.deny_domains {
            rules.push(FilterRule {
                action: FilterAction::Deny,
                subject: "network".into(),
                detail: format!("deny domain={}", domain),
            });
        }
        for domain in &permissions.network.allow_domains {
            rules.push(FilterRule {
                action: FilterAction::Allow,
                subject: "network".into(),
                detail: format!("allow domain={}", domain),
            });
        }
        if let Some(bw) = &permissions.network.max_bandwidth {
            rules.push(FilterRule {
                action: FilterAction::Log,
                subject: "network".into(),
                detail: format!("throttle bandwidth={}", bw),
            });
        }
        // Default-deny fallback: block any domain not explicitly allowed above.
        // This is always emitted after per-domain allow rules, ensuring unlisted
        // destinations are blocked regardless of whether the allow list is empty.
        rules.push(FilterRule {
            action: FilterAction::Deny,
            subject: "network".into(),
            detail: "deny domain=*".into(),
        });

        // --- Process / exec rules -------------------------------------------
        for cmd in &permissions.processes.deny {
            rules.push(FilterRule {
                action: FilterAction::Deny,
                subject: "process".into(),
                detail: format!("deny exec={}", cmd),
            });
        }
        for cmd in &permissions.processes.allow {
            rules.push(FilterRule {
                action: FilterAction::Allow,
                subject: "process".into(),
                detail: format!("allow exec={}", cmd),
            });
        }
        // Default-deny process execution unless explicitly allowed.
        if !permissions.processes.allow.contains(&"*".to_string()) {
            rules.push(FilterRule {
                action: FilterAction::Deny,
                subject: "process".into(),
                detail: "deny exec=*".into(),
            });
        }

        // --- Resource limit rules -------------------------------------------
        if let Some(cpu) = &permissions.resources.max_cpu {
            rules.push(FilterRule {
                action: FilterAction::Log,
                subject: "resource".into(),
                detail: format!("limit cpu={}", cpu),
            });
        }
        if let Some(mem) = &permissions.resources.max_memory {
            rules.push(FilterRule {
                action: FilterAction::Log,
                subject: "resource".into(),
                detail: format!("limit memory={}", mem),
            });
        }
        if let Some(disk) = &permissions.resources.max_disk {
            rules.push(FilterRule {
                action: FilterAction::Log,
                subject: "resource".into(),
                detail: format!("limit disk={}", disk),
            });
        }
        if let Some(fds) = &permissions.resources.max_open_files {
            rules.push(FilterRule {
                action: FilterAction::Log,
                subject: "resource".into(),
                detail: format!("limit open_files={}", fds),
            });
        }

        // --- GPU rules ------------------------------------------------------
        if permissions.gpu.enabled {
            if permissions.gpu.devices.is_empty() {
                rules.push(FilterRule {
                    action: FilterAction::Allow,
                    subject: "gpu".into(),
                    detail: "allow device=*".into(),
                });
            } else {
                for dev in &permissions.gpu.devices {
                    rules.push(FilterRule {
                        action: FilterAction::Allow,
                        subject: "gpu".into(),
                        detail: format!("allow device={}", dev),
                    });
                }
            }
        } else {
            rules.push(FilterRule {
                action: FilterAction::Deny,
                subject: "gpu".into(),
                detail: "deny device=*".into(),
            });
        }

        // Warn if the target is platform-specific and we're on the wrong host.
        // The actual translation is done by sandcastle-platform; we just emit abstract rules.
        tracing::debug!(
            target = ?target,
            rule_count = rules.len(),
            "Generated abstract filter"
        );

        Ok(GeneratedFilter { target, rules })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::*;

    /// Helper: build a minimal Permissions with empty everything.
    fn empty_permissions() -> Permissions {
        Permissions {
            filesystem: FsPermissions {
                allow_read: vec![],
                allow_write: vec![],
                deny: vec![],
            },
            network: NetworkPermissions {
                allow_domains: vec![],
                deny_domains: vec![],
                max_bandwidth: None,
            },
            processes: ProcessPermissions {
                allow: vec![],
                deny: vec![],
            },
            resources: ResourceLimits {
                max_cpu: None,
                max_memory: None,
                max_disk: None,
                max_open_files: None,
            },
            gpu: GpuPermissions {
                enabled: false,
                devices: vec![],
            },
        }
    }

    #[test]
    fn deny_rules_precede_allow_rules() {
        // A filter with both deny and allow filesystem entries should emit
        // deny rules before allow rules for each category.
        let mut perms = empty_permissions();
        perms.filesystem.deny = vec!["/secret/**".into()];
        perms.filesystem.allow_read = vec!["/public/**".into()];

        let filter = FilterGenerator::generate(&perms, FilterTarget::SeccompBpf).unwrap();

        // Find the indices of the first filesystem deny and the first filesystem allow.
        let first_deny = filter
            .rules
            .iter()
            .position(|r| r.subject == "filesystem" && r.action == FilterAction::Deny && r.detail.contains("/secret"))
            .expect("expected a filesystem deny rule for /secret");
        let first_allow = filter
            .rules
            .iter()
            .position(|r| r.subject == "filesystem" && r.action == FilterAction::Allow)
            .expect("expected a filesystem allow rule");

        assert!(
            first_deny < first_allow,
            "deny rule (index {first_deny}) must come before allow rule (index {first_allow})"
        );
    }

    #[test]
    fn default_deny_always_emitted() {
        // Even with allow entries, the generated filter must end each category
        // section with a deny-all fallback.
        let mut perms = empty_permissions();
        perms.filesystem.allow_read = vec!["/home/**".into()];
        perms.network.allow_domains = vec!["example.com".into()];

        let filter = FilterGenerator::generate(&perms, FilterTarget::LandlockRuleset).unwrap();

        let has_fs_deny_all = filter
            .rules
            .iter()
            .any(|r| r.subject == "filesystem" && r.action == FilterAction::Deny && r.detail == "deny path=*");
        let has_net_deny_all = filter
            .rules
            .iter()
            .any(|r| r.subject == "network" && r.action == FilterAction::Deny && r.detail == "deny domain=*");

        assert!(has_fs_deny_all, "filesystem deny-all fallback must be emitted");
        assert!(has_net_deny_all, "network deny-all fallback must be emitted");
    }

    #[test]
    fn empty_permissions_produce_deny_all() {
        let perms = empty_permissions();
        let filter = FilterGenerator::generate(&perms, FilterTarget::WindowsJobObject).unwrap();

        // With empty permissions there should be no Allow rules at all.
        let allow_count = filter
            .rules
            .iter()
            .filter(|r| r.action == FilterAction::Allow)
            .count();
        assert_eq!(allow_count, 0, "empty permissions must not produce any Allow rules");

        // But deny-all fallbacks must still be present for filesystem, network, process, gpu.
        let deny_all_subjects: Vec<&str> = filter
            .rules
            .iter()
            .filter(|r| r.action == FilterAction::Deny && (r.detail.ends_with("=*") || r.detail.ends_with("device=*")))
            .map(|r| r.subject.as_str())
            .collect();
        assert!(deny_all_subjects.contains(&"filesystem"));
        assert!(deny_all_subjects.contains(&"network"));
        assert!(deny_all_subjects.contains(&"process"));
        assert!(deny_all_subjects.contains(&"gpu"));
    }
}
