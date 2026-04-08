//! Linux sandbox implementation using kernel namespaces, Landlock LSM,
//! seccomp-BPF syscall filtering, and cgroup-v2 resource controls.
//!
//! # Security architecture
//!
//! A Linux sandbox combines several independent kernel mechanisms to build
//! defence-in-depth.  No single layer is sufficient on its own, so all four
//! are applied together:
//!
//! | Layer | Kernel feature | What it restricts |
//! |-------|---------------|-------------------|
//! | Filesystem | Landlock LSM | Which paths the process may open |
//! | Syscalls | seccomp-BPF | Which system calls the process may make |
//! | Namespaces | clone(2) flags | PID, mount, network, user isolation |
//! | Resources | cgroup-v2 | CPU time, memory, open file descriptors |

use crate::error::PlatformError;
use crate::sandbox::{Sandbox, SandboxConfig, SandboxStatus};
use sandcastle_policy::permission::{FilesystemPermission, NetworkPermission, ResourceLimits};
use sandcastle_policy::SandboxProfile;
use std::process::{Child, Command, ExitStatus};
use tracing::{debug, info, warn};

/// A sandboxed process on Linux.
pub struct LinuxSandbox {
    id: String,
    config: SandboxConfig,
    status: SandboxStatus,
    child: Option<Child>,
}

impl Sandbox for LinuxSandbox {
    fn create(config: SandboxConfig) -> Result<Self, PlatformError> {
        let id = uuid::Uuid::new_v4().to_string();
        info!(sandbox_id = %id, command = %config.command, "creating Linux sandbox");

        // Apply isolation layers before forking.  Each function logs its
        // intended behaviour; real kernel calls will replace the stubs when
        // the sandcastle-linux-primitives feature is stabilised.
        apply_landlock(&config.profile)?;
        apply_seccomp(&config.profile)?;
        setup_namespaces(&config)?;
        apply_cgroups(&config.profile.permissions.resources)?;

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

        info!(sandbox_id = %self.id, command = %self.config.command, "starting sandboxed process");

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
        info!(sandbox_id = %self.id, ?status, "sandboxed process exited");
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
                Err(e) if e.kind() == ErrorKind::InvalidInput => {
                    // Process already exited — not an error
                }
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

/// Configure Landlock LSM rules derived from the sandbox profile's filesystem
/// permissions.
///
/// Landlock is a Linux Security Module (≥ 5.13) that lets unprivileged
/// processes restrict their own filesystem access via a set of access-control
/// rules (ruleset).  Rules are applied with `landlock_create_ruleset(2)`,
/// `landlock_add_rule(2)`, and `landlock_restrict_self(2)`.
///
/// The stub logs the rules that *would* be applied without making any syscalls.
/// Real implementation will use the `landlock` crate once the feature gate is
/// stabilised.
fn apply_landlock(profile: &SandboxProfile) -> Result<(), PlatformError> {
    warn!("STUB: Landlock filesystem isolation is NOT actually enforced — the process has unrestricted filesystem access");
    let fs = &profile.permissions.filesystem;
    debug!(
        allow_read = ?fs.allow_read,
        allow_write = ?fs.allow_write,
        deny = ?fs.deny,
        "landlock: would apply filesystem ruleset (stub)"
    );
    Ok(())
}

/// Build and load a seccomp-BPF filter that allows only syscalls needed by the
/// trust level.
///
/// seccomp (secure computing mode) filters are compiled to BPF bytecode and
/// loaded with `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, …)`.  The filter
/// runs in kernel space for every syscall and can either allow, deny, or kill
/// the process.
///
/// The stub logs the filter that *would* be loaded.  The real implementation
/// will use the `seccomp` crate and generate a deny-all-then-allowlist policy
/// based on `profile.trust_level`.
fn apply_seccomp(profile: &SandboxProfile) -> Result<(), PlatformError> {
    warn!("STUB: seccomp-BPF syscall filtering is NOT actually enforced — all syscalls are permitted");
    debug!(
        trust_level = ?profile.trust_level,
        "seccomp: would load BPF filter for trust level (stub)"
    );
    Ok(())
}

/// Create a new set of Linux namespaces for the sandboxed process.
///
/// Namespaces partition global kernel resources so that each sandbox sees its
/// own isolated view:
///
/// - **User namespace** — maps the agent's UID/GID to an unprivileged range,
///   so the agent appears as root inside the sandbox but has no real privileges.
/// - **Mount namespace** — provides an independent mount table, enabling a
///   read-only bind-mount overlay of the host filesystem.
/// - **Network namespace** — isolates network interfaces; a sandboxed process
///   with no network permission sees only a loopback device.
/// - **PID namespace** — the agent's process tree starts at PID 1, preventing
///   it from signalling arbitrary host processes.
///
/// Created with `clone(2)` or `unshare(2)` (from the `nix` crate when compiled
/// on Linux).  The stub logs the flags that *would* be passed.
fn setup_namespaces(config: &SandboxConfig) -> Result<(), PlatformError> {
    warn!("STUB: Linux namespace isolation is NOT actually enforced — process runs in the host namespace");
    let net_allowed = !config.profile.permissions.network.allow_domains.is_empty();
    debug!(
        network_isolated = !net_allowed,
        "namespaces: would create user+mount+pid namespace (stub)"
    );
    Ok(())
}

/// Apply cgroup-v2 resource limits to the sandbox's cgroup.
///
/// cgroups v2 (control groups) is the Linux kernel mechanism for limiting,
/// accounting, and isolating resource usage of process groups.  SandCastle
/// writes limits to:
///
/// - `memory.max` — hard memory cap (OOM-kills exceeding processes)
/// - `cpu.max` — CPU quota/period pair (e.g., 50% of one core)
/// - `pids.max` — maximum number of PIDs (limits fork bombs)
///
/// The stub logs the limits that *would* be written to the cgroup hierarchy.
fn apply_cgroups(limits: &ResourceLimits) -> Result<(), PlatformError> {
    warn!("STUB: cgroup-v2 resource limits are NOT actually enforced — process has unrestricted resource access");
    debug!(
        max_memory = ?limits.max_memory,
        max_cpu = ?limits.max_cpu,
        max_open_files = ?limits.max_open_files,
        "cgroups: would write resource limits to cgroup-v2 hierarchy (stub)"
    );
    Ok(())
}

// uuid is used for sandbox ID generation
#[allow(unused_imports)]
use uuid;
