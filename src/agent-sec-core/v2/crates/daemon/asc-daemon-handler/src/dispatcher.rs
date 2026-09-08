use std::io::Write;
use std::sync::Arc;

use asc_action_runtime::{CancellationSignal, ExecutionContext, NeverCancels};
use asc_daemon_core::{
    PeerCredentials, PolicyAdministration, Principal, PrincipalPolicy, PrincipalRole,
    PromptScanning,
};
use asc_daemon_protocol::method::{self, AccessPolicy, MethodId};
use asc_daemon_protocol::{
    DaemonRequest, DaemonResponse, MAX_DAEMON_ERROR_MESSAGE_BYTES, RequestId, error_code,
};
use asc_daemon_service::{
    DispatchControl, DispatchError, DispatchRequest, RequestDispatcher, ResponseDisposition,
};

use crate::action::ActionHandler;
use crate::pap::PapHandler;

/// Protocol router composed over daemon application use cases.
pub struct DaemonDispatcher {
    pap: PapHandler,
    action: ActionHandler,
    principal_policy: Arc<dyn PrincipalPolicy>,
}

impl DaemonDispatcher {
    /// Composes PAP and Action dispatch with trusted server authorization.
    ///
    /// The role is process-owned configuration. It is never decoded from the
    /// request or inferred from caller-supplied attribution.
    pub fn new(
        application: impl PolicyAdministration + 'static,
        prompt_scanning: Arc<dyn PromptScanning>,
        principal_policy: Arc<dyn PrincipalPolicy>,
    ) -> Self {
        Self {
            pap: PapHandler::new(application),
            action: ActionHandler::new(prompt_scanning),
            principal_policy,
        }
    }

    /// Handles one decoded request without a cancellation source.
    ///
    /// In-process callers (tests, one-shot use) route through here; the
    /// service transport uses [`dispatch`](RequestDispatcher::dispatch), which
    /// supplies the peer's real deadline and cancellation signal.
    pub fn handle(
        &self,
        request_id: RequestId,
        peer: PeerCredentials,
        request: DaemonRequest,
    ) -> DaemonResponse {
        let signal = NeverCancels;
        let context = ExecutionContext::new(None, &signal);
        self.route(request_id, peer, request, &context)
    }

    /// Resolves, authorizes, and routes one request to its handler.
    fn route(
        &self,
        request_id: RequestId,
        peer: PeerCredentials,
        request: DaemonRequest,
        context: &ExecutionContext<'_>,
    ) -> DaemonResponse {
        let Some(method_id) = method::resolve(&request.method) else {
            return DaemonResponse::error(
                request_id,
                error_code::UNKNOWN_METHOD,
                "daemon method is not implemented",
            );
        };

        let role = self.principal_policy.role_for(peer);
        let principal = Principal::from_authenticated_peer(peer, role);
        if !is_authorized(&principal, method_id.metadata().access) {
            return DaemonResponse::error(
                request_id,
                error_code::PERMISSION_DENIED,
                "principal is not authorized to administer policy",
            );
        }
        match method_id {
            MethodId::Pap(method) => {
                self.pap
                    .handle(request_id, &principal, method, request.params)
            }
            MethodId::Action(method) => {
                self.action
                    .handle(request_id, context, method, request.params)
            }
        }
    }
}

fn is_authorized(principal: &Principal, access: AccessPolicy) -> bool {
    match access {
        AccessPolicy::PolicyAdministrator => principal.role() == PrincipalRole::PolicyAdministrator,
        // Any peer the transport has authenticated may reach a data-plane
        // capability; both roles clear this bar.
        AccessPolicy::AuthenticatedCaller => matches!(
            principal.role(),
            PrincipalRole::LocalUser | PrincipalRole::PolicyAdministrator
        ),
    }
}

/// Bridges the service's dispatch lifetime to the Action cancellation port.
///
/// Borrows the [`DispatchControl`] for the invocation so the runtime polls the
/// same signal the transport flips on deadline or shutdown, keeping a single
/// source of truth for whether the peer is still waiting.
struct DispatchCancellation<'a> {
    control: &'a DispatchControl,
}

impl CancellationSignal for DispatchCancellation<'_> {
    fn is_cancelled(&self) -> bool {
        self.control.is_cancelled()
    }
}

impl RequestDispatcher for DaemonDispatcher {
    fn dispatch(
        &self,
        request: DispatchRequest,
        response: &mut dyn Write,
    ) -> Result<ResponseDisposition, DispatchError> {
        let request_id = new_request_id();
        if request.control.is_cancelled() {
            return write_response(
                response,
                &DaemonResponse::<serde_json::Value>::error(
                    request_id,
                    error_code::DEADLINE_EXCEEDED,
                    "request dispatch deadline expired",
                ),
            );
        }

        let peer = PeerCredentials::new(request.peer.uid(), request.peer.gid(), request.peer.pid());
        let Ok(decoded) = serde_json::from_slice::<DaemonRequest>(&request.payload) else {
            return write_response(
                response,
                &DaemonResponse::<serde_json::Value>::error(
                    request_id,
                    error_code::INVALID_REQUEST,
                    "request envelope is invalid",
                ),
            );
        };
        let cancellation = DispatchCancellation {
            control: &request.control,
        };
        let context = ExecutionContext::new(Some(request.control.deadline()), &cancellation);
        write_response(response, &self.route(request_id, peer, decoded, &context))
    }
}

/// Public daemon-error message when decoded parameters cannot be shown safely.
pub(crate) const INVALID_PARAMETER_MESSAGE: &str = "request parameters are invalid";

/// Renders a serde decode failure into a bounded, caller-safe message.
///
/// A serde error can echo an oversized offending field; when it would exceed
/// the public error budget, a fixed message is returned instead so no
/// unbounded caller input is reflected back.
pub(crate) fn bounded_parameter_error(error: &serde_json::Error) -> String {
    let message = error.to_string();
    if message.len() > MAX_DAEMON_ERROR_MESSAGE_BYTES {
        INVALID_PARAMETER_MESSAGE.to_owned()
    } else {
        message
    }
}

pub(crate) fn new_request_id() -> RequestId {
    RequestId::new(uuid::Uuid::new_v4().to_string())
        .expect("UUID request identities are always non-empty")
}

pub(crate) fn write_response<T: serde::Serialize>(
    response: &mut dyn Write,
    value: &DaemonResponse<T>,
) -> Result<ResponseDisposition, DispatchError> {
    serde_json::to_writer(response, value).map_err(|_| DispatchError)?;
    Ok(ResponseDisposition::Send)
}
