#![allow(unsafe_code)]
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
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use tracing::{debug, info};

/// A sandboxed process on macOS.
///
/// The sandbox is enforced via `sandbox_init(3)`, which applies an SBPL
/// (Sandbox Profile Language) policy to the child process before it execs
/// the target command.  The SBPL profile is generated at creation time from
/// the [`SandboxProfile`] and stored here so that `start()` can pass it
/// into the `pre_exec` hook.
pub struct MacOSSandbox {
    id: String,
    config: SandboxConfig,
    status: SandboxStatus,
    child: Option<Child>,
    sbpl_profile: String,
}

impl Sandbox for MacOSSandbox {
    fn create(config: SandboxConfig) -> Result<Self, PlatformError> {
        let id = uuid::Uuid::new_v4().to_string();
        info!(sandbox_id = %id, command = %config.command, "creating macOS sandbox");

        let sbpl_profile = generate_sandbox_profile(&config.profile)?;
        debug!(sandbox_id = %id, profile = %sbpl_profile, "generated SBPL profile");

        setup_endpoint_security(&config.profile)?;
        setup_lima_vm_if_needed(&config)?;

        Ok(Self {
            id,
            config,
            status: SandboxStatus::Created,
            child: None,
            sbpl_profile,
        })
    }

    fn start(&mut self) -> Result<(), PlatformError> {
        if self.status == SandboxStatus::Running {
            return Err(PlatformError::ExecFailed(
                "sandbox is already running".into(),
            ));
        }

        info!(sandbox_id = %self.id, command = %self.config.command, "starting sandboxed process (macOS)");

        let mut cmd = Command::new(&self.config.command);
        cmd.args(&self.config.args)
            .current_dir(&self.config.working_dir);

        for (k, v) in &self.config.env {
            cmd.env(k, v);
        }

        // Apply the SBPL sandbox profile to the child process via sandbox_init(3).
        //
        // sandbox_init is called inside pre_exec, which runs in the forked child
        // *before* exec.  This means the sandbox policy is already active by the
        // time the target binary starts executing.
        //
        // Although sandbox_init is marked deprecated in macOS headers, it remains
        // functional through macOS 14 (Sonoma) and is the most reliable way to
        // apply an SBPL profile programmatically without requiring the
        // sandbox-exec binary.
        let sbpl = self.sbpl_profile.clone();
        unsafe {
            cmd.pre_exec(move || {
                use std::ffi::CString;

                extern "C" {
                    /// Apply a sandbox profile to the current process.
                    ///
                    /// - `profile`: null-terminated SBPL string (when flags = SANDBOX_NAMED)
                    /// - `flags`: `SANDBOX_NAMED` (0x0001) means `profile` is an SBPL
                    ///   string, not a predefined profile name.
                    /// - `errorbuf`: on failure, set to a malloc'd error description.
                    ///
                    /// Returns 0 on success, -1 on failure.
                    fn sandbox_init(
                        profile: *const std::ffi::c_char,
                        flags: u64,
                        errorbuf: *mut *mut std::ffi::c_char,
                    ) -> i32;

                    /// Free an error buffer returned by `sandbox_init`.
                    fn sandbox_free_error(errorbuf: *mut std::ffi::c_char);
                }

                const SANDBOX_NAMED: u64 = 0x0001;

                let c_profile = CString::new(sbpl.as_str()).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "SBPL profile contains null byte",
                    )
                })?;

                let mut errorbuf: *mut std::ffi::c_char = std::ptr::null_mut();
                let result = sandbox_init(c_profile.as_ptr(), SANDBOX_NAMED, &mut errorbuf);

                if result != 0 {
                    let err_msg = if !errorbuf.is_null() {
                        let msg =
                            std::ffi::CStr::from_ptr(errorbuf).to_string_lossy().to_string();
                        sandbox_free_error(errorbuf);
                        msg
                    } else {
                        "unknown sandbox_init error".to_string()
                    };
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        err_msg,
                    ));
                }

                Ok(())
            });
        }

        let child = cmd.spawn().map_err(|e| {
            PlatformError::ExecFailed(format!(
                "failed to spawn sandboxed '{}': {e}",
                self.config.command
            ))
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

    // Allow the target command (and any child processes it spawns) to execute.
    // Without this rule, the deny-default policy would block execve(2) itself.
    sbpl.push_str("(allow process-exec*)\n");
    sbpl.push_str("(allow process-fork)\n");

    for path in &profile.permissions.filesystem.allow_read {
        let escaped = escape_sbpl_path(path)?;
        sbpl.push_str(&format!("(allow file-read* (subpath \"{escaped}\"))\n"));
    }
    for path in &profile.permissions.filesystem.allow_write {
        let escaped = escape_sbpl_path(path)?;
        sbpl.push_str(&format!("(allow file-write* (subpath \"{escaped}\"))\n"));
    }
    if !profile.permissions.network.allow_domains.is_empty() {
        sbpl.push_str("(allow network-outbound)\n");
    }

    Ok(sbpl)
}

/// Sanitise a file path before interpolating it into an SBPL string literal.
///
/// SBPL uses a Scheme-like syntax where `"` terminates a string, `(` and `)`
/// delimit S-expressions, and `\` is the escape character.  Newlines and null
/// bytes could alter the profile semantics.  This function rejects paths that
/// contain any of these dangerous characters rather than trying to escape them,
/// because macOS `sandbox-exec` does not document a reliable escaping scheme.
fn escape_sbpl_path(path: &str) -> Result<String, PlatformError> {
    for ch in path.chars() {
        match ch {
            '"' | '(' | ')' | '\\' | '\n' | '\r' | '\0' => {
                return Err(PlatformError::CreateFailed(format!(
                    "SBPL path contains forbidden character {ch:?}: {path}"
                )));
            }
            _ => {}
        }
    }
    Ok(path.to_string())
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
