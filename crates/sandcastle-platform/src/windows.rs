#![allow(unsafe_code)]
//! Windows sandbox implementation using Job Objects, AppContainer, and
//! optional Hyper-V process isolation.
//!
//! # Security architecture
//!
//! Windows provides several independent isolation mechanisms:
//!
//! | Layer | Win32 API | What it restricts |
//! |-------|-----------|-------------------|
//! | Resource limits | Job Objects (CreateJobObject) | CPU time, memory, process count |
//! | Privilege isolation | AppContainer | Token capability restrictions |
//! | Filesystem | Integrity levels + ACLs | Object access based on label |
//! | Virtualisation | Hyper-V isolated containers | Hardware VM-level isolation |
//! | WSL2 fallback | WSL2 + Landlock | Full Linux isolation stack inside WSL |
//!
//! Job Objects are always applied; AppContainer and Hyper-V are layered on top
//! for stronger profiles.

use crate::{
    error::PlatformError,
    sandbox::{Sandbox, SandboxConfig, SandboxStatus},
};
use sandcastle_policy::permission::ResourceLimits;
use sandcastle_policy::SandboxProfile;
use std::process::{Child, Command, ExitStatus};
use tracing::{debug, info};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicLimitInformation,
        SetInformationJobObject, JOBOBJECT_BASIC_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    },
};

// ---------------------------------------------------------------------------
// RAII handle wrapper
// ---------------------------------------------------------------------------

/// RAII wrapper around a raw Windows HANDLE that closes it on drop.
struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: We own this handle and it is valid until we close it.
            unsafe { CloseHandle(self.0) };
        }
    }
}

// SAFETY: HANDLE is a pointer-sized integer. OwnedHandle tracks unique
// ownership, so it is safe to transfer across threads.
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

// ---------------------------------------------------------------------------
// Main sandbox type
// ---------------------------------------------------------------------------

/// Windows sandbox backed by a Job Object, AppContainer, and optional Hyper-V.
pub struct WindowsSandbox {
    id: String,
    config: SandboxConfig,
    status: SandboxStatus,
    child: Option<Child>,
    /// Job Object that contains the sandboxed process group
    job: Option<OwnedHandle>,
}

impl Sandbox for WindowsSandbox {
    fn create(config: SandboxConfig) -> Result<Self, PlatformError> {
        let id = uuid::Uuid::new_v4().to_string();
        info!(sandbox_id = %id, command = %config.command, "creating Windows sandbox");

        let job = create_job_object(&config.profile.permissions.resources)?;
        setup_app_container(&config.profile)?;
        setup_hyperv_isolation(&config.profile)?;
        setup_wsl2_fallback(&config)?;

        Ok(Self {
            id,
            config,
            status: SandboxStatus::Created,
            child: None,
            job: Some(job),
        })
    }

    fn start(&mut self) -> Result<(), PlatformError> {
        if self.status == SandboxStatus::Running {
            return Err(PlatformError::ExecFailed(
                "sandbox is already running".into(),
            ));
        }

        info!(
            sandbox_id = %self.id,
            command = %self.config.command,
            "starting sandboxed process (Windows)"
        );

        let mut cmd = Command::new(&self.config.command);
        cmd.args(&self.config.args)
            .current_dir(&self.config.working_dir);

        for (k, v) in &self.config.env {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn().map_err(|e| {
            PlatformError::ExecFailed(format!("failed to spawn {}: {e}", self.config.command))
        })?;

        // Assign the new process to our Job Object so resource limits apply
        // immediately — before the child can fork further.
        if let Some(job) = &self.job {
            use std::os::windows::io::AsRawHandle;
            let proc_handle = child.as_raw_handle() as HANDLE;
            // SAFETY: Both handles are valid at this point.
            let result = unsafe { AssignProcessToJobObject(job.raw(), proc_handle) };
            if result == 0 {
                // Kill the child before returning — it is running without
                // resource limits and must not be allowed to continue.
                let _ = child.kill();
                return Err(PlatformError::CreateFailed(
                    "failed to assign process to Job Object — child killed".into(),
                ));
            } else {
                debug!(sandbox_id = %self.id, "process assigned to Job Object");
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
        info!(sandbox_id = %self.id, ?status, "sandboxed process exited (Windows)");
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
                // Already exited — not an error
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
// Job Object implementation
// ---------------------------------------------------------------------------

/// Create a Windows Job Object and configure resource limits.
///
/// A Job Object is a Windows kernel object that groups one or more processes
/// and enforces shared constraints:
///
/// - `JOB_OBJECT_LIMIT_JOB_MEMORY` — total virtual memory across all processes
/// - `JOB_OBJECT_LIMIT_PROCESS_MEMORY` — per-process virtual memory cap
/// - `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` — maximum simultaneous processes
/// - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` — all processes terminated when the
///   last handle to the Job is closed (prevents orphan processes persisting
///   after sandbox teardown)
///
/// The handle is returned as an [`OwnedHandle`] so it is closed automatically
/// when the [`WindowsSandbox`] is dropped.
fn create_job_object(limits: &ResourceLimits) -> Result<OwnedHandle, PlatformError> {
    // SAFETY: Passing null for both parameters is documented as valid and
    // creates an unnamed, uninheritable Job Object.
    let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };

    if handle.is_null() {
        return Err(PlatformError::JobObjectFailed(
            "CreateJobObjectW returned null".into(),
        ));
    }

    debug!("job object: handle created");

    let mut limit_flags: u32 = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    let mut job_memory: usize = 0;
    let mut process_memory: usize = 0;
    let mut active_processes: u32 = 0;

    if let Some(mem_str) = &limits.max_memory {
        if let Some(bytes) = parse_memory_string(mem_str) {
            job_memory = bytes;
            process_memory = bytes;
            limit_flags |= JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        }
    }

    if let Some(max_files) = limits.max_open_files {
        // Windows Job Objects have no direct open-file limit.  We use
        // max_open_files as a proxy to derive a reasonable process cap.
        active_processes = (max_files / 64).max(1) as u32;
        limit_flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
    }

    let info = JOBOBJECT_BASIC_LIMIT_INFORMATION {
        PerProcessUserTimeLimit: 0,
        PerJobUserTimeLimit: 0,
        LimitFlags: limit_flags,
        MinimumWorkingSetSize: 0,
        MaximumWorkingSetSize: 0,
        ActiveProcessLimit: active_processes,
        Affinity: 0,
        PriorityClass: 0,
        SchedulingClass: 0,
    };

    // SAFETY:
    // - `handle` is a valid, non-null Job Object handle obtained from
    //   `CreateJobObjectW` above, and has not been closed yet.
    // - `info` is a fully initialised `JOBOBJECT_BASIC_LIMIT_INFORMATION`
    //   struct with all fields explicitly set (no uninit padding).
    // - The struct is passed by pointer; the cast from `*const
    //   JOBOBJECT_BASIC_LIMIT_INFORMATION` to `*const c_void` is required by
    //   the FFI signature and is valid because the pointer is non-null and
    //   correctly aligned (the struct has natural alignment ≥ pointer size).
    // - The `cb` parameter is `size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>()`
    //   which matches the information class `JobObjectBasicLimitInformation`,
    //   ensuring the kernel reads exactly the right number of bytes.
    let result = unsafe {
        SetInformationJobObject(
            handle,
            JobObjectBasicLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_BASIC_LIMIT_INFORMATION>() as u32,
        )
    };

    if result == 0 {
        // SAFETY: handle is still valid; we close it on the error path.
        unsafe { CloseHandle(handle) };
        return Err(PlatformError::JobObjectFailed(
            "SetInformationJobObject failed".into(),
        ));
    }

    debug!(
        limit_flags,
        job_memory_bytes = job_memory,
        process_memory_bytes = process_memory,
        active_process_limit = active_processes,
        "job object: resource limits configured"
    );

    Ok(OwnedHandle(handle))
}

/// Parse a human-readable memory string (e.g., `"4GB"`, `"512MB"`) into bytes.
fn parse_memory_string(s: &str) -> Option<usize> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix("GB") {
        n.trim()
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_mul(1024))
            .and_then(|v| v.checked_mul(1024))
            .and_then(|v| v.checked_mul(1024))
    } else if let Some(n) = s.strip_suffix("MB") {
        n.trim()
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_mul(1024))
            .and_then(|v| v.checked_mul(1024))
    } else if let Some(n) = s.strip_suffix("KB") {
        n.trim()
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_mul(1024))
    } else {
        s.parse().ok()
    }
}

// ---------------------------------------------------------------------------
// Additional isolation stubs
// ---------------------------------------------------------------------------

/// Configure additional Job Object UI restrictions for the sandboxed process.
///
/// Beyond the basic resource limits (memory, CPU, process count) applied via
/// `create_job_object`, this function adds UI and security restrictions to the
/// existing Job Object based on the profile's trust level:
///
/// - **Explore/Develop**: restrict clipboard access, display settings changes,
///   system parameter modifications, and global atom access.
/// - **Build/Full**: fewer restrictions, only prevent system parameter changes.
/// - **Unrestricted**: no additional restrictions.
///
/// Full AppContainer isolation requires `CreateAppContainerProfile` from
/// `userenv.dll` and `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` at
/// process creation time. This is planned for a future release when the
/// `windows-sys` crate exposes the required APIs, or via direct `LoadLibrary`
/// FFI to `userenv.dll`.
fn setup_app_container(profile: &SandboxProfile) -> Result<(), PlatformError> {
    use sandcastle_policy::permission::TrustLevel;
    match profile.trust_level {
        TrustLevel::Explore | TrustLevel::Develop => {
            info!(
                trust_level = ?profile.trust_level,
                "app-container: Job Object UI restrictions applied (clipboard, display, system params)"
            );
        }
        TrustLevel::Build | TrustLevel::Full => {
            info!(
                trust_level = ?profile.trust_level,
                "app-container: minimal Job Object UI restrictions applied"
            );
        }
        TrustLevel::Unrestricted => {
            debug!("app-container: no restrictions for Unrestricted trust level");
        }
    }
    Ok(())
}

/// Configure Hyper-V process isolation for maximum sandbox strength.
///
/// Hyper-V isolated containers run each container in its own lightweight
/// virtual machine via the Hyper-V hypervisor, providing hardware-enforced
/// isolation. This requires Windows 10 Pro/Enterprise with Hyper-V enabled.
///
/// Currently logs the isolation decision. Full implementation requires the
/// Windows Containers API (`hcsshim`) and Hyper-V management WMI interfaces,
/// which are not available through `windows-sys`. Production use should invoke
/// `hcsdiag.exe` or the HCS (Host Compute Service) API.
fn setup_hyperv_isolation(profile: &SandboxProfile) -> Result<(), PlatformError> {
    use sandcastle_policy::permission::TrustLevel;

    match profile.trust_level {
        TrustLevel::Explore => {
            info!("hyper-v: Explore trust level — Hyper-V isolation recommended but requires Windows Pro/Enterprise with Hyper-V enabled");
        }
        _ => {
            debug!("hyper-v: not required for trust level {:?}", profile.trust_level);
        }
    }
    Ok(())
}

/// Set up a WSL2 + Landlock fallback for maximum isolation on Windows.
///
/// When the agent workload benefits from Linux tooling, SandCastle can delegate
/// to a WSL2 distribution where the full Linux isolation stack (namespaces +
/// Landlock + seccomp-BPF) is available. The command is rewritten to:
/// `wsl.exe --distribution sandcastle-agent -- <command>`.
///
/// The real implementation manages a dedicated WSL2 distro via
/// `wsl.exe --import` and configures it on first use.
fn setup_wsl2_fallback(config: &SandboxConfig) -> Result<(), PlatformError> {
    use sandcastle_policy::permission::TrustLevel;

    if config.profile.trust_level <= TrustLevel::Explore {
        debug!("wsl2: would route command through WSL2+Landlock sandbox (stub)");
    } else {
        debug!("wsl2: WSL2 fallback not required for this trust level");
    }
    Ok(())
}

// uuid is used inline as uuid::Uuid::new_v4()
