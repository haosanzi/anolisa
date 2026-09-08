//! Execution outcome contracts shared by every Action.

use serde::{Deserialize, Serialize};

/// Business outcome of one Action that ran to completion.
///
/// There is deliberately no `error` variant. An Action that could not run
/// returns [`ActionError`] instead, so an outage can never be read as either
/// "high risk detected" or "input is safe". `Result<_, ActionError>` is
/// therefore the only execution-status signal; a parallel status enum would
/// only create a second source of truth that can disagree with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Nothing notable found by the layers that answered.
    Pass,
    /// Suspicious, but not confirmed by an authoritative layer.
    Warn,
    /// Confirmed high-risk input.
    Deny,
}

impl Verdict {
    /// Returns the stable wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Deny => "deny",
        }
    }
}

/// Stable failure class of an Action invocation that produced no verdict.
///
/// Kinds exist to be projected onto transport error codes exactly once, at
/// the daemon boundary; capabilities classify, they do not name wire codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionErrorKind {
    /// Request content is unusable; retrying it unchanged cannot succeed.
    InvalidInput,
    /// A required backing service or model is not currently usable.
    DependencyUnavailable,
    /// The invocation left its dispatch lifetime before completing.
    Cancelled,
    /// Defect or unexpected state, with detail withheld from the caller.
    Internal,
}

impl ActionErrorKind {
    /// Returns the stable audit and log value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::DependencyUnavailable => "dependency_unavailable",
            Self::Cancelled => "cancelled",
            Self::Internal => "internal",
        }
    }
}

/// Caller-safe failure of one Action invocation.
///
/// The message is expected to reach an operator, so implementations must
/// keep it free of scanned content and internal paths. The transport bounds
/// its length; this type does not.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ActionError {
    kind: ActionErrorKind,
    message: String,
}

impl ActionError {
    /// Creates a rejection of unusable request content.
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(ActionErrorKind::InvalidInput, message)
    }

    /// Creates a failure caused by an unusable backing dependency.
    pub fn dependency_unavailable(message: impl Into<String>) -> Self {
        Self::new(ActionErrorKind::DependencyUnavailable, message)
    }

    /// Creates a failure for an invocation abandoned before completion.
    pub fn cancelled(message: impl Into<String>) -> Self {
        Self::new(ActionErrorKind::Cancelled, message)
    }

    /// Creates an internal failure with caller-safe detail only.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ActionErrorKind::Internal, message)
    }

    fn new(kind: ActionErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Returns the failure class used for transport projection.
    pub const fn kind(&self) -> ActionErrorKind {
        self.kind
    }

    /// Returns the caller-safe explanation.
    pub fn message(&self) -> &str {
        &self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_wire_values_stay_lower_snake_case() {
        for (verdict, expected) in [
            (Verdict::Pass, "pass"),
            (Verdict::Warn, "warn"),
            (Verdict::Deny, "deny"),
        ] {
            assert_eq!(verdict.as_str(), expected);
            assert_eq!(
                serde_json::to_value(verdict).expect("verdict serializes"),
                serde_json::json!(expected)
            );
        }
    }

    #[test]
    fn verdict_has_no_failure_variant_on_the_wire() {
        // A scanner outage must not be expressible as a verdict; it is an
        // ActionError. Guard the wire form so adding one is a visible break.
        assert!(serde_json::from_value::<Verdict>(serde_json::json!("error")).is_err());
    }

    #[test]
    fn errors_keep_their_class_and_message() {
        let error = ActionError::dependency_unavailable("model service is unreachable");
        assert_eq!(error.kind(), ActionErrorKind::DependencyUnavailable);
        assert_eq!(error.message(), "model service is unreachable");
        assert_eq!(error.to_string(), "model service is unreachable");
    }
}
