//! Windows-specific sandbox implementation using Job Objects and AppContainer.
//!
//! Stub — full Windows isolation will be implemented in a subsequent milestone.

use crate::{
    error::PlatformError,
    sandbox::{Sandbox, SandboxConfig, SandboxStatus},
};
use std::process::ExitStatus;

/// Windows sandbox backed by a Job Object and optional AppContainer.
pub struct WindowsSandbox {
    id: String,
    status: SandboxStatus,
}

impl Sandbox for WindowsSandbox {
    fn create(config: SandboxConfig) -> Result<Self, PlatformError> {
        Ok(Self {
            id: uuid::Uuid::new_v4().to_string(),
            status: SandboxStatus::Created,
        })
    }

    fn start(&mut self) -> Result<(), PlatformError> {
        self.status = SandboxStatus::Running;
        Ok(())
    }

    fn wait(&mut self) -> Result<ExitStatus, PlatformError> {
        Err(PlatformError::Unsupported(
            "Windows sandbox wait not yet implemented".into(),
        ))
    }

    fn status(&self) -> SandboxStatus {
        self.status.clone()
    }

    fn terminate(&mut self) -> Result<(), PlatformError> {
        self.status = SandboxStatus::Stopped;
        Ok(())
    }

    fn id(&self) -> &str {
        &self.id
    }
}
