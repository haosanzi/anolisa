//! Projects one approved Cedar policy set onto the OS permission set a sandbox backend accepts.
//!
//! Bind mounts expose whole paths with read and write rights, so the projection keeps the coarse
//! part of the policy and reports everything else as [`ProjectionReport::unprojected`]. Runtime
//! facts (write operation, argv, interpreter, agent identity) stay with the PDP: it evaluates the
//! same policy per request and narrows this permission set further, never widens it.

#![forbid(unsafe_code)]

mod project;

use asc_os_permission_types::{NetworkMode, OsPermissionSet};
use serde::Serialize;

pub use project::ProjectError;

/// Filesystem and network grants recovered from the policy text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectionReport {
    /// Paths a `file.read` permit covers.
    pub read_paths: Vec<String>,
    /// Paths a `file.write` permit covers with both rights.
    pub write_paths: Vec<String>,
    /// Paths whose direct execution a `file.exec` forbid removes.
    pub noexec_paths: Vec<String>,
    /// Network mode implied by the presence of a `network.use` permit.
    pub network: NetworkMode,
    /// Whether a permit covers `process.spawn` or `file.exec`, without which every launch is
    /// denied before the permission set is even considered.
    pub launch_permitted: bool,
    /// Statements the OS layer cannot express; the PDP still enforces them per request.
    pub unprojected: Vec<String>,
    /// Projection output the operator must act on, such as a writable path no `file.read` permit
    /// covers; the PDP then denies that write because a write also needs read access.
    pub warnings: Vec<String>,
}

/// Default-deny permission set a PEP asks the PDP for, plus what the projection recovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SandboxProfile {
    /// Requested permissions; the PDP narrows them against the same policy.
    pub permissions: OsPermissionSet,
    /// Operator-facing account of the projection.
    pub report: ProjectionReport,
}

/// Projects Cedar text into a default-deny sandbox profile.
///
/// Only literal paths in positive `file.read`, `file.write` and `file.exec` predicates become OS
/// permissions. Negated, globbed or otherwise reshaped path expressions are reported instead of
/// being approximated, and unlisted paths stay denied.
///
/// # Errors
/// Rejects unparsable text, linked templates, oversized policy sets and permission sets that the
/// OS contract itself refuses.
pub fn project(text: &str) -> Result<SandboxProfile, ProjectError> {
    project::project(text)
}
