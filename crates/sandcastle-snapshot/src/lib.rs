#![forbid(unsafe_code)]
//! Sandbox state snapshot, restore, and checkpoint management for SandCastle.
//!
//! Provides CoW snapshots, branching, restoration, and diffing for sandboxed
//! environments. Snapshots are stored as directory copies on disk with a JSON
//! index for fast lookup.

pub mod error;
pub mod snapshot;
pub mod store;
pub mod branch;
pub mod diff;

pub use error::SnapshotError;
pub use snapshot::{Snapshot, SnapshotMetadata};
pub use store::SnapshotStore;
pub use branch::BranchManager;
pub use diff::{SnapshotDiff, DiffEntry, DiffType};
