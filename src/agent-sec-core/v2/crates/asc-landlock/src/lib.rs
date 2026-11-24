//! Restrict a program and its children with a static Landlock file access policy.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

mod island;
mod launch;
mod policy;

pub use launch::{exec, install};

const MAX_PATHS: usize = 512;

/// Failure to prepare the policy, install the ruleset, or execute the target.
#[derive(Debug, thiserror::Error)]
pub enum LandlockError {
    /// The launch or policy exceeds the statically enforceable subset.
    #[error("{0}")]
    Invalid(String),
    /// A Cedar policy failed the shared schema or syntax checks.
    #[error(transparent)]
    Cedar(#[from] asc_policy_cedar::CedarError),
    /// A Cedar source envelope could not be decoded.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// An Island filesystem policy could not be decoded.
    #[error("invalid Island TOML policy: {0}")]
    IslandToml(#[from] toml::de::Error),
    /// The required kernel ruleset could not be installed in full.
    #[error("cannot fully enforce Landlock ruleset: {0}")]
    Kernel(String),
    /// A filesystem or process-control operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// A Linux filesystem operation failed.
    #[error(transparent)]
    Fs(#[from] rustix::io::Errno),
}

fn invalid(message: impl std::fmt::Display) -> LandlockError {
    LandlockError::Invalid(message.to_string())
}

fn validate_path(path: &str) -> Result<(), LandlockError> {
    if !path.starts_with('/')
        || path.contains(['\0', '*', '?', '[', ']', '{', '}', '\\'])
        || (path != "/" && path.ends_with('/'))
        || path.contains("//")
        || path.split('/').any(|part| matches!(part, "." | ".."))
    {
        return Err(invalid(format!(
            "expected a canonical absolute path: {path}"
        )));
    }
    Ok(())
}
