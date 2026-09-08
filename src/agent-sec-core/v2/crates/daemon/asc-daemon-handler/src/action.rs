//! Action data-plane protocol adapter invoked by the daemon dispatcher.

use std::sync::Arc;

use asc_action_runtime::ExecutionContext;
use asc_action_types::{ActionError, ActionErrorKind, PromptScanRequest};
use asc_daemon_core::PromptScanning;
use asc_daemon_protocol::method::ActionMethod;
use asc_daemon_protocol::{DaemonResponse, RequestId, error_code};

use crate::dispatcher::bounded_parameter_error;

/// Action protocol adapter with the concrete scanner type erased.
///
/// Unlike PAP dispatch, an Action carries a per-invocation
/// [`ExecutionContext`] so a long scan bails out for a caller who has already
/// left. The port keeps the model-client and rule-engine dependencies out of
/// this crate; only the binary that builds the scanner links them.
pub(super) struct ActionHandler {
    scanning: Arc<dyn PromptScanning>,
}

impl ActionHandler {
    pub(super) fn new(scanning: Arc<dyn PromptScanning>) -> Self {
        Self { scanning }
    }

    pub(super) fn handle(
        &self,
        request_id: RequestId,
        context: &ExecutionContext<'_>,
        method: ActionMethod,
        params: serde_json::Value,
    ) -> DaemonResponse {
        match method {
            ActionMethod::PromptScan => self.prompt_scan(request_id, context, params),
        }
    }

    fn prompt_scan(
        &self,
        request_id: RequestId,
        context: &ExecutionContext<'_>,
        params: serde_json::Value,
    ) -> DaemonResponse {
        let request: PromptScanRequest = match serde_json::from_value(params) {
            Ok(request) => request,
            // A malformed wire shape is a request fault, distinct from
            // domain validation, which the capability reports as an
            // `invalid_argument` ActionError below.
            Err(error) => {
                return DaemonResponse::error(
                    request_id,
                    error_code::INVALID_REQUEST,
                    &bounded_parameter_error(&error),
                );
            }
        };
        match self.scanning.scan(context, &request) {
            Ok(output) => match serde_json::to_value(output) {
                Ok(value) => DaemonResponse::success(request_id, value),
                Err(_) => DaemonResponse::error(
                    request_id,
                    error_code::INTERNAL,
                    "scan result could not be encoded",
                ),
            },
            Err(error) => {
                let code = project_action_error(&error);
                DaemonResponse::error(request_id, code, error.message())
            }
        }
    }
}

/// Projects an [`ActionError`] class onto its transport error code.
///
/// This is the single place a capability's failure class becomes a wire code,
/// mirroring the PAP handler's projection. The message is authored by the
/// capability to be caller-safe and is bounded by the response type.
fn project_action_error(error: &ActionError) -> &'static str {
    match error.kind() {
        ActionErrorKind::InvalidInput => error_code::INVALID_ARGUMENT,
        ActionErrorKind::DependencyUnavailable => error_code::UNAVAILABLE,
        ActionErrorKind::Cancelled => error_code::DEADLINE_EXCEEDED,
        ActionErrorKind::Internal => error_code::INTERNAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_error_classes_map_to_stable_wire_codes() {
        assert_eq!(
            project_action_error(&ActionError::invalid_input("x")),
            error_code::INVALID_ARGUMENT
        );
        assert_eq!(
            project_action_error(&ActionError::dependency_unavailable("x")),
            error_code::UNAVAILABLE
        );
        assert_eq!(
            project_action_error(&ActionError::cancelled("x")),
            error_code::DEADLINE_EXCEEDED
        );
        assert_eq!(
            project_action_error(&ActionError::internal("x")),
            error_code::INTERNAL
        );
    }
}
