#![forbid(unsafe_code)]
//! GPU passthrough management for SandCastle AI agent sandboxes.
//!
//! Supports three isolation techniques:
//! - **nvproxy** — gVisor syscall filtering for NVIDIA GPUs (Linux)
//! - **VFIO** — hardware-level PCI passthrough, one GPU per sandbox (Linux)
//! - **GPU-PV** — Hyper-V paravirtualized GPU access (Windows)
//! - **Direct** — process-level sandboxing only, fallback (macOS / unknown)

pub mod detect;
pub mod error;
pub mod gpu_pv;
pub mod nvproxy;
pub mod passthrough;
pub mod vfio;

mod guard;

pub use detect::{GpuInfo, GpuVendor, PassthroughMethod};
pub use error::GpuError;
pub use guard::GpuGuard;
pub use passthrough::{GpuPassthrough, GpuPassthroughConfig};
