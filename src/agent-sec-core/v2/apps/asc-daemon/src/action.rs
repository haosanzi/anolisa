//! Composition-root wiring of the concrete `prompt_scan` capability.

use asc_action_runtime::{ActionRuntime, ExecutionContext};
use asc_action_types::{ActionError, PromptScanOutput, PromptScanRequest};
use asc_capability_prompt_scan::PromptScanExecutor;
use asc_daemon_core::PromptScanning;

/// The daemon's concrete `prompt_scan` capability.
///
/// Owns the executor and its reused scanners for the process lifetime. This
/// is the only component that links the model-client and rule-engine
/// dependencies; the handler and core crates see only the [`PromptScanning`]
/// port, so the transport layers stay free of the detection engine.
pub struct PromptScanService {
    runtime: ActionRuntime<PromptScanExecutor>,
}

impl PromptScanService {
    /// Builds the service and its always-ready `fast` scanner.
    ///
    /// # Errors
    /// Returns [`ActionError`] when the rule engine cannot be constructed,
    /// which is a build defect rather than a request problem.
    pub fn new() -> Result<Self, ActionError> {
        Ok(Self {
            runtime: ActionRuntime::new(PromptScanExecutor::new()?),
        })
    }
}

impl PromptScanning for PromptScanService {
    fn scan(
        &self,
        context: &ExecutionContext<'_>,
        request: &PromptScanRequest,
    ) -> Result<PromptScanOutput, ActionError> {
        self.runtime.run(context, request)
    }
}
