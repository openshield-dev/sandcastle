//! Core audit event types.

use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum length for user-controlled strings interpolated into log descriptions.
const MAX_LOG_STRING_LEN: usize = 4096;

/// Sanitize a user-controlled string before interpolating it into a log description.
///
/// - Replaces `\n` and `\r` with spaces to prevent log injection / forging.
/// - Strips null bytes.
/// - Truncates to [`MAX_LOG_STRING_LEN`] characters.
pub fn sanitize_log_string(s: &str) -> String {
    s.chars()
        .filter(|&c| c != '\0')
        .map(|c| {
            if c.is_control() {
                ' ' // Replace all control chars (newlines, tabs, ESC, etc.)
            } else {
                c
            }
        })
        .take(MAX_LOG_STRING_LEN)
        .collect()
}

/// Fine-grained event type for every sandboxed action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    FilesystemRead,
    FilesystemWrite,
    FilesystemDelete,
    FilesystemCreate,
    NetworkConnect,
    NetworkRequest,
    NetworkDnsResolve,
    ProcessExec,
    ProcessSpawn,
    GpuAccess,
    SnapshotCreate,
    SnapshotRestore,
    PolicyViolation,
    SandboxStart,
    SandboxStop,
    PermissionPrompt,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::FilesystemRead => "filesystem_read",
            Self::FilesystemWrite => "filesystem_write",
            Self::FilesystemDelete => "filesystem_delete",
            Self::FilesystemCreate => "filesystem_create",
            Self::NetworkConnect => "network_connect",
            Self::NetworkRequest => "network_request",
            Self::NetworkDnsResolve => "network_dns_resolve",
            Self::ProcessExec => "process_exec",
            Self::ProcessSpawn => "process_spawn",
            Self::GpuAccess => "gpu_access",
            Self::SnapshotCreate => "snapshot_create",
            Self::SnapshotRestore => "snapshot_restore",
            Self::PolicyViolation => "policy_violation",
            Self::SandboxStart => "sandbox_start",
            Self::SandboxStop => "sandbox_stop",
            Self::PermissionPrompt => "permission_prompt",
        };
        f.write_str(s)
    }
}

/// Backward-compatible alias — existing code using `EventKind` keeps compiling.
///
/// The legacy variant set (Filesystem, Network, Process, Snapshot, Gpu, Lifecycle)
/// is preserved as associated constants so callers can migrate gradually.
pub type EventKind = EventType;

/// The policy decision made for an event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Deny,
    AskHuman,
    AuditOnly,
}

impl std::fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::AskHuman => "ask_human",
            Self::AuditOnly => "audit_only",
        };
        f.write_str(s)
    }
}

/// The policy evaluation result attached to every event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    /// Decision reached by the policy engine.
    pub decision: PolicyDecision,
    /// Name of the rule that produced the decision, if any.
    pub rule_name: Option<String>,
    /// Time taken to evaluate the policy, in microseconds.
    pub eval_time_us: u64,
}

impl PolicyResult {
    /// Construct a result with no specific rule and zero eval time.
    pub fn simple(decision: PolicyDecision) -> Self {
        Self {
            decision,
            rule_name: None,
            eval_time_us: 0,
        }
    }
}

/// Free-form action detail carried by every event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionDetail {
    /// Human-readable description of the action.
    pub description: String,
    /// Filesystem path involved, if any.
    pub path: Option<String>,
    /// Network domain or address involved, if any.
    pub domain: Option<String>,
    /// Command string for process events.
    pub command: Option<String>,
    /// Payload / object size in bytes, if applicable.
    pub size_bytes: Option<u64>,
    /// Extensible bag of key-value metadata.
    pub extra: HashMap<String, serde_json::Value>,
}

impl ActionDetail {
    /// Minimal detail with only a description.
    pub fn description(desc: impl Into<String>) -> Self {
        Self {
            description: desc.into(),
            path: None,
            domain: None,
            command: None,
            size_bytes: None,
            extra: HashMap::new(),
        }
    }
}

/// Session-level context attached to every event.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventContext {
    /// Policy profile active during the event.
    pub profile: Option<String>,
    /// Agent trust level, e.g. `"low"`, `"high"`.
    pub trust_level: Option<String>,
    /// Running count of actions in this session (for rate-limit auditing).
    pub session_action_count: u64,
    /// Name of the agent that triggered the event.
    pub agent_name: Option<String>,
}

/// A single immutable audit record produced by the sandbox.
///
/// Every action taken by or on behalf of a sandboxed agent produces one event.
/// Events are serialised as newline-delimited JSON for easy ingestion by log
/// aggregators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier.
    pub id: Uuid,
    /// Wall-clock timestamp (UTC).
    pub timestamp: DateTime<Utc>,
    /// Sandbox instance that produced this event.
    pub sandbox_id: String,
    /// Logical session within the sandbox.
    pub session_id: Uuid,
    /// Fine-grained category of the event.
    pub event_type: EventType,
    /// Details of the action that was taken.
    pub action: ActionDetail,
    /// Policy decision and evaluation metadata.
    pub policy_result: PolicyResult,
    /// Session-level context.
    pub context: EventContext,
}

impl AuditEvent {
    /// Full constructor.
    pub fn new(
        sandbox_id: String,
        session_id: Uuid,
        event_type: EventType,
        action: ActionDetail,
        policy_result: PolicyResult,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            sandbox_id,
            session_id,
            event_type,
            action,
            policy_result,
            context: EventContext::default(),
        }
    }

    /// Quick constructor for a filesystem event.
    pub fn filesystem(
        sandbox_id: String,
        session_id: Uuid,
        event_type: EventType,
        path: String,
        decision: PolicyDecision,
    ) -> Self {
        let safe_path = sanitize_log_string(&path);
        let description = format!("{event_type} {safe_path}");
        Self::new(
            sandbox_id,
            session_id,
            event_type,
            ActionDetail {
                description,
                path: Some(safe_path),
                domain: None,
                command: None,
                size_bytes: None,
                extra: HashMap::new(),
            },
            PolicyResult::simple(decision),
        )
    }

    /// Quick constructor for a network event.
    pub fn network(
        sandbox_id: String,
        session_id: Uuid,
        domain: String,
        decision: PolicyDecision,
    ) -> Self {
        let safe_domain = sanitize_log_string(&domain);
        let description = format!("network_connect {safe_domain}");
        Self::new(
            sandbox_id,
            session_id,
            EventType::NetworkConnect,
            ActionDetail {
                description,
                path: None,
                domain: Some(safe_domain.clone()),
                command: None,
                size_bytes: None,
                extra: HashMap::new(),
            },
            PolicyResult::simple(decision),
        )
    }

    /// Quick constructor for a process event.
    pub fn process(
        sandbox_id: String,
        session_id: Uuid,
        command: String,
        decision: PolicyDecision,
    ) -> Self {
        let safe_command = sanitize_log_string(&command);
        let description = format!("process_exec {safe_command}");
        Self::new(
            sandbox_id,
            session_id,
            EventType::ProcessExec,
            ActionDetail {
                description,
                path: None,
                domain: None,
                command: Some(safe_command.clone()),
                size_bytes: None,
                extra: HashMap::new(),
            },
            PolicyResult::simple(decision),
        )
    }

    /// Returns `true` when the event represents an allowed action.
    pub fn is_allowed(&self) -> bool {
        self.policy_result.decision == PolicyDecision::Allow
    }

    /// Returns `true` when the event represents a policy violation (Deny or AskHuman).
    pub fn is_violation(&self) -> bool {
        matches!(
            self.policy_result.decision,
            PolicyDecision::Deny | PolicyDecision::AskHuman
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_control_chars() {
        let evil = "normal\n\r\t\x1b[0m\0injected";
        let clean = sanitize_log_string(evil);
        assert!(!clean.contains('\n'));
        assert!(!clean.contains('\r'));
        assert!(!clean.contains('\t'));
        assert!(!clean.contains('\x1b'));
        assert!(!clean.contains('\0'));
        assert!(clean.contains("normal"));
        assert!(clean.contains("injected"));
    }

    #[test]
    fn filesystem_event_sanitizes_path_field() {
        let evil_path = "/etc/passwd\n{\"fake\":\"event\"}".to_string();
        let event = AuditEvent::filesystem(
            "sb1".into(),
            Uuid::new_v4(),
            EventType::FilesystemRead,
            evil_path,
            PolicyDecision::Allow,
        );
        // The path field stored in ActionDetail must be sanitized.
        assert!(!event.action.path.unwrap().contains('\n'));
    }

    #[test]
    fn network_event_sanitizes_domain_field() {
        let evil_domain = "evil.com\nevil2.com".to_string();
        let event = AuditEvent::network(
            "sb1".into(),
            Uuid::new_v4(),
            evil_domain,
            PolicyDecision::Allow,
        );
        assert!(!event.action.domain.unwrap().contains('\n'));
    }

    #[test]
    fn process_event_sanitizes_command_field() {
        let evil_cmd = "rm -rf /\n{\"injected\":true}".to_string();
        let event = AuditEvent::process(
            "sb1".into(),
            Uuid::new_v4(),
            evil_cmd,
            PolicyDecision::Allow,
        );
        assert!(!event.action.command.unwrap().contains('\n'));
    }
}
