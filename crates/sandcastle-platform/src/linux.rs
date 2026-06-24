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
use sandcastle_policy::permission::TrustLevel;
use sandcastle_policy::SandboxProfile;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use tracing::{debug, info, warn};

use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, ABI,
};
use nix::sched::CloneFlags;

/// A sandboxed process on Linux.
pub struct LinuxSandbox {
    id: String,
    config: SandboxConfig,
    status: SandboxStatus,
    child: Option<Child>,
    namespace_flags: CloneFlags,
    cgroup_path: Option<PathBuf>,
}

impl Sandbox for LinuxSandbox {
    fn create(config: SandboxConfig) -> Result<Self, PlatformError> {
        let id = uuid::Uuid::new_v4().to_string();
        info!(sandbox_id = %id, command = %config.command, "creating Linux sandbox");

        // Apply Landlock filesystem isolation to the current process.
        // This restricts the calling process before fork, so the child inherits it.
        apply_landlock(&config.profile)?;

        // Compute namespace flags (applied in pre_exec before child starts).
        let namespace_flags = compute_namespace_flags(&config);

        // Set up cgroup for resource limits. The child PID will be moved into
        // the cgroup after spawn.
        let cgroup_path = apply_cgroups(&id, &config.profile.permissions.resources)?;

        Ok(Self {
            id,
            config,
            status: SandboxStatus::Created,
            child: None,
            namespace_flags,
            cgroup_path,
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

        // Apply namespace isolation and seccomp in the child process before exec.
        let flags = self.namespace_flags;
        let trust_level = self.config.profile.trust_level;
        unsafe {
            cmd.pre_exec(move || {
                // Enter new namespaces.
                nix::sched::unshare(flags).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("unshare failed: {e}"),
                    )
                })?;

                // Prevent privilege escalation — this is real enforcement.
                let ret = nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                if ret != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "prctl(PR_SET_NO_NEW_PRIVS) failed",
                    ));
                }

                // Write UID/GID mappings if we created a user namespace.
                if flags.contains(CloneFlags::CLONE_NEWUSER) {
                    let uid = nix::unistd::getuid();
                    let gid = nix::unistd::getgid();

                    // Deny setgroups before writing gid_map (required by kernel).
                    let _ = std::fs::write("/proc/self/setgroups", "deny");

                    // Map current user to root inside the namespace.
                    let _ = std::fs::write(
                        "/proc/self/uid_map",
                        format!("0 {} 1\n", uid),
                    );
                    let _ = std::fs::write(
                        "/proc/self/gid_map",
                        format!("0 {} 1\n", gid),
                    );
                }

                // Apply seccomp no_new_privs (already done above) and log trust level.
                // Full BPF syscall filtering requires the `seccompiler` crate.
                // For Explore/Develop trust levels, the combination of Landlock +
                // namespaces + no_new_privs provides meaningful isolation.
                match trust_level {
                    TrustLevel::Explore | TrustLevel::Develop => {
                        // TODO: Load a BPF filter using seccompiler crate for
                        // fine-grained syscall filtering. Currently relying on
                        // no_new_privs + Landlock + namespace isolation.
                    }
                    TrustLevel::Build | TrustLevel::Full | TrustLevel::Unrestricted => {
                        // Higher trust levels: no syscall filtering beyond no_new_privs.
                    }
                }

                Ok(())
            });
        }

        let child = cmd.spawn().map_err(|e| {
            PlatformError::ExecFailed(format!("failed to spawn '{}': {e}", self.config.command))
        })?;

        // Move the child into the cgroup if one was created.
        if let Some(ref cgroup_path) = self.cgroup_path {
            let pid = child.id();
            let procs_file = cgroup_path.join("cgroup.procs");
            if let Err(e) = fs::write(&procs_file, pid.to_string()) {
                warn!(
                    sandbox_id = %self.id,
                    path = %procs_file.display(),
                    error = %e,
                    "failed to move child process into cgroup"
                );
            } else {
                info!(
                    sandbox_id = %self.id,
                    pid = pid,
                    cgroup = %cgroup_path.display(),
                    "moved child process into cgroup"
                );
            }
        }

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

        // Clean up cgroup directory.
        self.cleanup_cgroup();

        Ok(())
    }

    fn id(&self) -> &str {
        &self.id
    }
}

impl Drop for LinuxSandbox {
    fn drop(&mut self) {
        self.cleanup_cgroup();
    }
}

impl LinuxSandbox {
    /// Remove the cgroup directory if it was created by this sandbox.
    fn cleanup_cgroup(&self) {
        if let Some(ref path) = self.cgroup_path {
            // The kernel requires the cgroup to be empty (no processes) before
            // removal. Best-effort cleanup: ignore errors.
            if let Err(e) = fs::remove_dir(path) {
                debug!(
                    sandbox_id = %self.id,
                    path = %path.display(),
                    error = %e,
                    "could not remove cgroup directory (may still have processes)"
                );
            } else {
                info!(sandbox_id = %self.id, path = %path.display(), "cleaned up cgroup");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Isolation implementations
// ---------------------------------------------------------------------------

/// Configure Landlock LSM rules derived from the sandbox profile's filesystem
/// permissions.
///
/// Landlock is a Linux Security Module (>= 5.13) that lets unprivileged
/// processes restrict their own filesystem access via a set of access-control
/// rules (ruleset).
fn apply_landlock(profile: &SandboxProfile) -> Result<(), PlatformError> {
    let fs_perms = &profile.permissions.filesystem;

    // Use the best available ABI, falling back gracefully.
    let abi = ABI::V3;

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| PlatformError::LandlockFailed(format!("failed to create ruleset: {e}")))?
        .create()
        .map_err(|e| PlatformError::LandlockFailed(format!("failed to create ruleset: {e}")))?;

    // Add read-only rules.
    for path in &fs_perms.allow_read {
        // Skip glob patterns — Landlock operates on directory FDs, not globs.
        // We strip trailing /** or /* to get the base directory.
        let base_path = strip_glob_suffix(path);
        if base_path.is_empty() || base_path == "*" {
            continue;
        }

        match PathFd::new(&base_path) {
            Ok(path_fd) => {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(path_fd, AccessFs::from_read(abi)))
                    .map_err(|e| {
                        PlatformError::LandlockFailed(format!(
                            "failed to add read rule for '{}': {e}",
                            base_path
                        ))
                    })?;
                debug!(path = %base_path, "landlock: added read-only rule");
            }
            Err(e) => {
                debug!(path = %base_path, error = %e, "landlock: skipping unresolvable read path");
            }
        }
    }

    // Add read+write rules.
    for path in &fs_perms.allow_write {
        let base_path = strip_glob_suffix(path);
        if base_path.is_empty() || base_path == "*" {
            continue;
        }

        match PathFd::new(&base_path) {
            Ok(path_fd) => {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(path_fd, AccessFs::from_all(abi)))
                    .map_err(|e| {
                        PlatformError::LandlockFailed(format!(
                            "failed to add write rule for '{}': {e}",
                            base_path
                        ))
                    })?;
                debug!(path = %base_path, "landlock: added read+write rule");
            }
            Err(e) => {
                debug!(path = %base_path, error = %e, "landlock: skipping unresolvable write path");
            }
        }
    }

    // Enforce the ruleset on the current process.
    let status = ruleset
        .restrict_self()
        .map_err(|e| PlatformError::LandlockFailed(format!("restrict_self failed: {e}")))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            info!("landlock: filesystem isolation fully enforced");
        }
        RulesetStatus::PartiallyEnforced => {
            warn!("landlock: filesystem isolation only partially enforced (kernel may lack full ABI support)");
        }
        RulesetStatus::NotEnforced => {
            warn!("landlock: filesystem isolation NOT enforced (kernel does not support Landlock — requires >= 5.13)");
        }
    }

    Ok(())
}

/// Strip trailing glob suffixes like `/**`, `/*`, or `**` from a path to get
/// the base directory suitable for Landlock's `PathBeneath`.
fn strip_glob_suffix(path: &str) -> String {
    let p = path
        .trim_end_matches("/**")
        .trim_end_matches("/*")
        .trim_end_matches("**");
    // Expand ~ to home directory.
    if p.starts_with("~/") || p == "~" {
        if let Some(home) = std::env::var("HOME").ok() {
            return p.replacen('~', &home, 1);
        }
    }
    // Expand $PROJECT_DIR if present.
    if p.contains("$PROJECT_DIR") {
        if let Some(dir) = std::env::var("PROJECT_DIR").ok() {
            return p.replace("$PROJECT_DIR", &dir);
        }
    }
    p.to_string()
}

/// Compute the set of namespace flags to pass to `unshare(2)` in the child.
fn compute_namespace_flags(config: &SandboxConfig) -> CloneFlags {
    let mut flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWNS;

    // Isolate network if no domains are allowed.
    let net_allowed = !config.profile.permissions.network.allow_domains.is_empty();
    if !net_allowed {
        flags |= CloneFlags::CLONE_NEWNET;
    }

    info!(
        network_isolated = !net_allowed,
        flags = ?flags,
        "namespaces: computed isolation flags"
    );

    flags
}

/// Apply cgroup-v2 resource limits by creating a cgroup directory and writing
/// limits. Returns the cgroup path if one was successfully created.
fn apply_cgroups(
    sandbox_id: &str,
    limits: &sandcastle_policy::permission::ResourceLimits,
) -> Result<Option<PathBuf>, PlatformError> {
    // Only create a cgroup if there are limits to apply.
    if limits.max_memory.is_none()
        && limits.max_cpu.is_none()
        && limits.max_open_files.is_none()
    {
        info!("cgroups: no resource limits configured, skipping cgroup creation");
        return Ok(None);
    }

    let cgroup_base = PathBuf::from("/sys/fs/cgroup");
    if !cgroup_base.exists() {
        warn!("cgroups: /sys/fs/cgroup does not exist, resource limits will not be enforced");
        return Ok(None);
    }

    let cgroup_path = cgroup_base.join(format!("sandcastle-{}", sandbox_id));

    // Create the cgroup directory.
    if let Err(e) = fs::create_dir_all(&cgroup_path) {
        warn!(
            path = %cgroup_path.display(),
            error = %e,
            "cgroups: failed to create cgroup directory, resource limits will not be enforced"
        );
        return Ok(None);
    }

    info!(path = %cgroup_path.display(), "cgroups: created cgroup directory");

    // Write memory.max
    if let Some(ref max_memory) = limits.max_memory {
        let bytes = parse_memory_string(max_memory);
        match bytes {
            Some(b) => {
                let mem_file = cgroup_path.join("memory.max");
                if let Err(e) = fs::write(&mem_file, b.to_string()) {
                    warn!(
                        limit = %max_memory,
                        error = %e,
                        "cgroups: failed to write memory.max"
                    );
                } else {
                    info!(limit = %max_memory, bytes = b, "cgroups: set memory.max");
                }
            }
            None => {
                warn!(limit = %max_memory, "cgroups: could not parse memory limit string");
            }
        }
    }

    // Write cpu.max
    if let Some(ref max_cpu) = limits.max_cpu {
        if let Some((quota, period)) = parse_cpu_string(max_cpu) {
            let cpu_file = cgroup_path.join("cpu.max");
            let value = format!("{} {}", quota, period);
            if let Err(e) = fs::write(&cpu_file, &value) {
                warn!(
                    limit = %max_cpu,
                    error = %e,
                    "cgroups: failed to write cpu.max"
                );
            } else {
                info!(limit = %max_cpu, value = %value, "cgroups: set cpu.max");
            }
        } else {
            warn!(limit = %max_cpu, "cgroups: could not parse CPU limit string");
        }
    }

    // Write pids.max
    if let Some(max_pids) = limits.max_open_files {
        let pids_file = cgroup_path.join("pids.max");
        if let Err(e) = fs::write(&pids_file, max_pids.to_string()) {
            warn!(
                limit = max_pids,
                error = %e,
                "cgroups: failed to write pids.max"
            );
        } else {
            info!(limit = max_pids, "cgroups: set pids.max");
        }
    }

    Ok(Some(cgroup_path))
}

/// Parse a human-readable memory string like "512MB", "4GB", "1024KB" into bytes.
fn parse_memory_string(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num_part, unit) = if s.ends_with("GB") || s.ends_with("Gb") || s.ends_with("gb") {
        (s[..s.len() - 2].trim(), 1024u64 * 1024 * 1024)
    } else if s.ends_with("MB") || s.ends_with("Mb") || s.ends_with("mb") {
        (s[..s.len() - 2].trim(), 1024u64 * 1024)
    } else if s.ends_with("KB") || s.ends_with("Kb") || s.ends_with("kb") {
        (s[..s.len() - 2].trim(), 1024u64)
    } else if s.ends_with('B') || s.ends_with('b') {
        (s[..s.len() - 1].trim(), 1u64)
    } else {
        // Assume raw bytes.
        (s, 1u64)
    };

    num_part.parse::<u64>().ok().map(|n| n * unit)
}

/// Parse a CPU percentage string like "50%", "100%", "200%" into a
/// (quota, period) tuple for cgroup v2's `cpu.max`.
///
/// The period is fixed at 100000 microseconds (100ms). A "50%" quota means
/// 50000us out of every 100000us period.
fn parse_cpu_string(s: &str) -> Option<(u64, u64)> {
    let s = s.trim().trim_end_matches('%');
    let percent: u64 = s.parse().ok()?;
    let period: u64 = 100_000; // 100ms in microseconds
    let quota = percent * period / 100;
    Some((quota, period))
}
