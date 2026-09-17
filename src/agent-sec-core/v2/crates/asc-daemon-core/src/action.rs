//! Authenticated scan application operations, composed over the shared lifecycle.
use crate::PeerCredentials;
use asc_action_runtime::{ExecutionControl, Invocation, InvokeError};
use asc_action_types::{
    ActionAttribution, ActionOutcome, CallerIdentity, CodeScanRequest, Correlation,
    PromptScanRequest,
};

/// Holds capability registrations assembled by the process composition root.
pub struct ActionService {
    code_scan: Box<dyn Invocation<CodeScanRequest>>,
    prompt_scan: Box<dyn Invocation<PromptScanRequest>>,
}

impl ActionService {
    /// Requires explicitly configured code- and prompt-scan invocation runtimes.
    #[must_use]
    pub fn new(
        code_scan: impl Invocation<CodeScanRequest> + 'static,
        prompt_scan: impl Invocation<PromptScanRequest> + 'static,
    ) -> Self {
        Self {
            code_scan: Box::new(code_scan),
            prompt_scan: Box::new(prompt_scan),
        }
    }

    /// Scans code for any authenticated local peer, without a role requirement.
    ///
    /// # Errors
    /// Returns a controlled internal failure after runtime finalization.
    pub fn code_scan(
        &self,
        peer: PeerCredentials,
        control: &ExecutionControl,
        request: &CodeScanRequest,
    ) -> Result<ActionOutcome, InvokeError> {
        self.code_scan.invoke(
            control,
            &ActionAttribution {
                caller: CallerIdentity {
                    uid: peer.uid(),
                    gid: peer.gid(),
                    pid: peer.pid(),
                },
                correlation: Correlation::default(),
                agent_name: None,
            },
            request,
        )
    }

    /// Scans a prompt for any authenticated local peer, without a role requirement.
    ///
    /// # Errors
    /// Returns a controlled internal failure after runtime finalization.
    pub fn prompt_scan(
        &self,
        peer: PeerCredentials,
        control: &ExecutionControl,
        request: &PromptScanRequest,
    ) -> Result<ActionOutcome, InvokeError> {
        self.prompt_scan.invoke(
            control,
            &ActionAttribution {
                caller: CallerIdentity {
                    uid: peer.uid(),
                    gid: peer.gid(),
                    pid: peer.pid(),
                },
                correlation: Correlation::default(),
                agent_name: None,
            },
            request,
        )
    }
}
