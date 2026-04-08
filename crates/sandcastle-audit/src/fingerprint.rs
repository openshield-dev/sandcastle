//! Agent behavior fingerprinting — learns what's "normal" for each agent
//! profile across runs and flags anomalies.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

use crate::event::{AuditEvent, EventType};

const SENSITIVE_PATH_PATTERNS: &[&str] = &[
    ".ssh/", ".aws/", ".gnupg/", "/etc/shadow", "/etc/passwd", ".env",
    "credentials.json", "service_account.json", "private_key", "id_rsa", "id_ed25519",
];

const SENSITIVE_DOMAINS: &[&str] = &["metadata.google.internal", "169.254.169.254"];

/// A fingerprint of an agent's typical behavior across multiple runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorFingerprint {
    pub profile: String,
    pub run_count: u64,
    pub known_paths: HashSet<String>,
    pub known_domains: HashSet<String>,
    pub known_commands: HashSet<String>,
    pub avg_events_per_run: f64,
    pub max_events_per_run: u64,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl BehaviorFingerprint {
    /// Create an empty fingerprint for a profile.
    pub fn new(profile: &str) -> Self {
        Self {
            profile: profile.to_string(),
            run_count: 0,
            known_paths: HashSet::new(),
            known_domains: HashSet::new(),
            known_commands: HashSet::new(),
            avg_events_per_run: 0.0,
            max_events_per_run: 0,
            updated_at: chrono::Utc::now(),
        }
    }

    /// Incorporate a run's events into this fingerprint.
    pub fn update(&mut self, events: &[AuditEvent]) {
        let count = events.len() as u64;
        let total = self.avg_events_per_run * self.run_count as f64 + count as f64;
        self.run_count += 1;
        self.avg_events_per_run = total / self.run_count as f64;
        if count > self.max_events_per_run {
            self.max_events_per_run = count;
        }
        // Cap set sizes to prevent unbounded growth over many runs.
        const MAX_SET_SIZE: usize = 10_000;
        for event in events {
            if let Some(ref p) = event.action.path {
                if self.known_paths.len() < MAX_SET_SIZE {
                    self.known_paths.insert(p.clone());
                }
            }
            if let Some(ref d) = event.action.domain {
                if self.known_domains.len() < MAX_SET_SIZE {
                    self.known_domains.insert(d.clone());
                }
            }
            if let Some(ref c) = event.action.command {
                if self.known_commands.len() < MAX_SET_SIZE {
                    self.known_commands.insert(c.clone());
                }
            }
        }
        self.updated_at = chrono::Utc::now();
    }

    /// Compare a new run against this fingerprint and return anomalies.
    pub fn analyze(&self, events: &[AuditEvent]) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        let count = events.len() as u64;

        if self.run_count > 0 && self.max_events_per_run > 0 && count > self.max_events_per_run * 2 {
            anomalies.push(Anomaly {
                severity: AnomalySeverity::Medium,
                category: "volume".into(),
                description: format!(
                    "Event count {count} exceeds 2x historical max ({})", self.max_events_per_run
                ),
                detail: format!("count={count}"),
            });
        }

        for event in events {
            if let Some(ref path) = event.action.path {
                if !self.known_paths.contains(path) {
                    let severity = if is_sensitive_path(path) {
                        AnomalySeverity::High
                    } else {
                        AnomalySeverity::Medium
                    };
                    anomalies.push(Anomaly {
                        severity,
                        category: "filesystem".into(),
                        description: "Access to previously unseen path".into(),
                        detail: path.clone(),
                    });
                }
            }
            if let Some(ref domain) = event.action.domain {
                if !self.known_domains.contains(domain) {
                    let severity = if is_sensitive_domain(domain) {
                        AnomalySeverity::High
                    } else {
                        AnomalySeverity::Medium
                    };
                    anomalies.push(Anomaly {
                        severity,
                        category: "network".into(),
                        description: "Contact with previously unseen domain".into(),
                        detail: domain.clone(),
                    });
                }
            }
            if let Some(ref cmd) = event.action.command {
                if !self.known_commands.contains(cmd) {
                    let severity = match event.event_type {
                        EventType::ProcessExec | EventType::ProcessSpawn => AnomalySeverity::Medium,
                        _ => AnomalySeverity::Low,
                    };
                    anomalies.push(Anomaly {
                        severity,
                        category: "process".into(),
                        description: "Execution of previously unseen command".into(),
                        detail: cmd.clone(),
                    });
                }
            }
        }
        anomalies
    }
}

fn is_sensitive_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    SENSITIVE_PATH_PATTERNS.iter().any(|p| lower.contains(p))
}

fn is_sensitive_domain(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    SENSITIVE_DOMAINS.iter().any(|d| lower.contains(d))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub severity: AnomalySeverity,
    pub category: String,
    pub description: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
}

/// Persistent store for fingerprints at `<store_path>/.sandcastle/fingerprints/{profile}.json`.
pub struct FingerprintStore {
    store_path: PathBuf,
}

impl FingerprintStore {
    pub fn open(store_path: PathBuf) -> Self {
        Self { store_path }
    }

    fn profile_path(&self, profile: &str) -> PathBuf {
        self.store_path.join(".sandcastle").join("fingerprints").join(format!("{profile}.json"))
    }

    pub fn load(&self, profile: &str) -> Option<BehaviorFingerprint> {
        let data = std::fs::read_to_string(self.profile_path(profile)).ok()?;
        match serde_json::from_str(&data) {
            Ok(fp) => Some(fp),
            Err(e) => {
                tracing::warn!(
                    profile = %profile,
                    error = %e,
                    "Fingerprint file is corrupted — starting fresh"
                );
                None
            }
        }
    }

    pub fn save(&self, fingerprint: &BehaviorFingerprint) -> Result<(), std::io::Error> {
        let path = self.profile_path(&fingerprint.profile);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(fingerprint)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        // Atomic write: write to temp file then rename to prevent corruption.
        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &json)?;
        std::fs::rename(&tmp_path, &path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::PolicyDecision;
    use uuid::Uuid;

    fn fs_ev(path: &str) -> AuditEvent {
        AuditEvent::filesystem("sb".into(), Uuid::new_v4(), EventType::FilesystemRead, path.into(), PolicyDecision::Allow)
    }
    fn net_ev(domain: &str) -> AuditEvent {
        AuditEvent::network("sb".into(), Uuid::new_v4(), domain.into(), PolicyDecision::Allow)
    }
    fn proc_ev(cmd: &str) -> AuditEvent {
        AuditEvent::process("sb".into(), Uuid::new_v4(), cmd.into(), PolicyDecision::Allow)
    }

    #[test]
    fn new_fingerprint_is_empty() {
        let fp = BehaviorFingerprint::new("test");
        assert_eq!(fp.run_count, 0);
        assert!(fp.known_paths.is_empty());
    }

    #[test]
    fn update_accumulates() {
        let mut fp = BehaviorFingerprint::new("a");
        fp.update(&[fs_ev("/tmp/x"), net_ev("api.example.com"), proc_ev("ls")]);
        assert_eq!(fp.run_count, 1);
        assert!(fp.known_paths.contains("/tmp/x"));
        assert!(fp.known_domains.contains("api.example.com"));
        assert!(fp.known_commands.contains("ls"));
        assert!((fp.avg_events_per_run - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn flags_unseen_path() {
        let mut fp = BehaviorFingerprint::new("b");
        fp.update(&[fs_ev("/tmp/ok")]);
        let a = fp.analyze(&[fs_ev("/etc/secret")]);
        assert_eq!(a[0].category, "filesystem");
    }

    #[test]
    fn sensitive_path_high() {
        let a = BehaviorFingerprint::new("c").analyze(&[fs_ev("/root/.ssh/id_rsa")]);
        assert_eq!(a[0].severity, AnomalySeverity::High);
    }

    #[test]
    fn sensitive_domain_high() {
        let a = BehaviorFingerprint::new("d").analyze(&[net_ev("169.254.169.254")]);
        assert_eq!(a[0].severity, AnomalySeverity::High);
    }

    #[test]
    fn known_items_no_anomalies() {
        let mut fp = BehaviorFingerprint::new("e");
        let evts = vec![fs_ev("/tmp/f"), net_ev("ok.com")];
        fp.update(&evts);
        assert!(fp.analyze(&evts).is_empty());
    }
}
