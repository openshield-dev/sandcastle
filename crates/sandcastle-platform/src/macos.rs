//! macOS sandbox implementation.
//!
//! # Security architecture
//!
//! macOS provides several isolation primitives that SandCastle can combine:
//!
//! | Layer | Apple API | What it restricts |
//! |-------|-----------|-------------------|
//! | Filesystem + IPC | `sandbox-exec` / Sandbox profiles | SBPL-based allow/deny rules |
//! | System events | Endpoint Security framework | File, process, and network events |
//! | Network | Network Extension framework | Packet-level egress filtering |
//! | Virtualisation | Lima / Apple Virtualization.framework | Full VM isolation |
//!
//! For macOS agents that require the strongest isolation, SandCastle can
//! delegate to a Lima VM, which runs a lightweight Linux guest where the full
//! Linux isolation stack (namespaces + Landlock + seccomp) is available.

use crate::error::PlatformError;
use crate::sandbox::{Sandbox, SandboxConfig, SandboxStatus};
use sandcastle_policy::SandboxProfile;
use std::process::{Child, Command, ExitStatus};
use tracing::{debug, info};

/// A sandboxed process on macOS.
pub struct MacOSSandbox {
    id: String,
    config: SandboxConfig,
    status: SandboxStatus,
    child: Option<Child>,
}

impl Sandbox for MacOSSandbox {
    fn create(config: SandboxConfig) -> Result<Self, PlatformError> {
        let id = uuid::Uuid::new_v4().to_string();
        info!(sandbox_id = %id, command = %config.command, "creating macOS sandbox");

        let profile_src = generate_sandbox_profile(&config.profile)?;
        debug!(profile = %profile_src, "sandbox-exec: would load SBPL profile (stub)");

        setup_endpoint_security(&config.profile)?;
        setup_lima_vm_if_needed(&config)?;

        Ok(Self {
            id,
            config,
            status: SandboxStatus::Created,
            child: None,
        })
    }

    fn start(&mut self) -> Result<(), PlatformError> {
        if self.status == SandboxStatus::Running {
            return Err(PlatformError::ExecFailed(
                "sandbox is already running".into(),
            ));
        }

        info!(sandbox_id = %self.id, command = %self.config.command, "starting sandboxed process (macOS)");

        // In a real implementation this would invoke `sandbox-exec -f <profile> <command>`.
        // For now we launch the command directly so the stub compiles and runs.
        let mut cmd = Command::new(&self.config.command);
        cmd.args(&self.config.args)
            .current_dir(&self.config.working_dir);

        for (k, v) in &self.config.env {
            cmd.env(k, v);
        }

        let child = cmd.spawn().map_err(|e| {
            PlatformError::ExecFailed(format!("failed to spawn '{}': {e}", self.config.command))
        })?;

        self.child = Some(child);
        self.status = SandboxStatus::Running;
        Ok(())
    }

    fn wait(&mut self) -> Result<ExitStatus, PlatformError> {
        let child = self.child.as_mut().ok_or(PlatformError::NotRunning)?;
        let status = child.wait().map_err(PlatformError::Io)?;
        self.status = SandboxStatus::Stopped;
        info!(sandbox_id = %self.id, ?status, "sandboxed process exited (macOS)");
        Ok(status)
    }

    fn status(&self) -> SandboxStatus {
        self.status.clone()
    }

    fn terminate(&mut self) -> Result<(), PlatformError> {
        use std::io::ErrorKind;

        if let Some(child) = self.child.as_mut() {
            match child.kill() {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::InvalidInput => {}
                Err(e) => return Err(PlatformError::Io(e)),
            }
        }
        self.status = SandboxStatus::Stopped;
        Ok(())
    }

    fn id(&self) -> &str {
        &self.id
    }
}

// ---------------------------------------------------------------------------
// Isolation stubs
// ---------------------------------------------------------------------------

/// Generate a Sandbox Profile Language (SBPL) document for `sandbox-exec`.
///
/// `sandbox-exec` is the userspace interface to the macOS kernel sandbox
/// (also known as Seatbelt).  It accepts a profile written in SBPL — a
/// Scheme-like language that lists `(allow ...)` and `(deny ...)` rules for
/// system operations such as `file-read*`, `network-outbound`, and
/// `process-exec`.
///
/// The generated profile starts with `(deny default)` (deny-all) and adds
/// explicit allow rules derived from `SandboxProfile.permissions`.
fn generate_sandbox_profile(profile: &SandboxProfile) -> Result<String, PlatformError> {
    let mut sbpl = String::from("(version 1)\n(deny default)\n");

    for path in &profile.permissions.filesystem.allow_read {
        sbpl.push_str(&format!("(allow file-read* (subpath \"{path}\"))\n"));
    }
    for path in &profile.permissions.filesystem.allow_write {
        sbpl.push_str(&format!("(allow file-write* (subpath \"{path}\"))\n"));
    }
    if !profile.permissions.network.allow_domains.is_empty() {
        sbpl.push_str("(allow network-outbound)\n");
    }

    Ok(sbpl)
}

/// Register an Endpoint Security client for the sandbox.
///
/// Apple's Endpoint Security framework (macOS 10.15+) provides a C API
/// (`es_new_client`, `es_subscribe`) that lets privileged system extensions
/// receive and respond to security-relevant events — file opens, process
/// launches, network connections — before they complete.
///
/// This stub would, in the real implementation, subscribe to `ES_EVENT_TYPE_AUTH_*`
/// events and authorise or deny them based on the sandbox profile.  This
/// requires the `com.apple.developer.endpoint-security.client` entitlement.
fn setup_endpoint_security(profile: &SandboxProfile) -> Result<(), PlatformError> {
    debug!(
        trust_level = ?profile.trust_level,
        "endpoint-security: would subscribe to ES_EVENT_TYPE_AUTH_* events (stub)"
    );
    Ok(())
}

/// Optionally spin up a Lima VM for maximum isolation.
///
/// Lima (<https://lima-vm.io>) manages lightweight Linux VMs on macOS via
/// Apple's Virtualization.framework.  When the profile's trust level demands
/// it, SandCastle can run the agent inside a Lima VM, giving it access to the
/// full Linux isolation stack (namespaces + Landlock + seccomp).
///
/// This stub checks whether a Lima VM is needed and logs the decision.
fn setup_lima_vm_if_needed(config: &SandboxConfig) -> Result<(), PlatformError> {
    use sandcastle_policy::permission::TrustLevel;

    if config.profile.trust_level <= TrustLevel::Explore {
        debug!("lima: would provision ephemeral Lima VM for maximum isolation (stub)");
    } else {
        debug!("lima: VM not required for this trust level");
    }
    Ok(())
}

#[allow(unused_imports)]
use uuid;
