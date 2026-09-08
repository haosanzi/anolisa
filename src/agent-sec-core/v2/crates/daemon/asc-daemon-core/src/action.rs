//! Transport-independent port for the daemon's Action data plane.

use asc_action_runtime::ExecutionContext;
use asc_action_types::{ActionError, PromptScanOutput, PromptScanRequest};

/// One `prompt_scan` invocation, decoupled from the detection engine.
///
/// The handler decodes and authorizes a request, then calls this port; the
/// composition root supplies the concrete scanner. Keeping the port here lets
/// the handler and core stay free of the capability's model-client and
/// rule-engine dependencies, which live only in the binary that builds the
/// scanner.
pub trait PromptScanning: Send + Sync {
    /// Scans `request` within the caller's dispatch lifetime.
    ///
    /// # Errors
    /// Returns [`ActionError`] when the request is unusable, a backing
    /// dependency is unavailable, the invocation was abandoned, or the engine
    /// hit an internal fault. There is deliberately no verdict for failure:
    /// an outage must never be read as a safe result.
    fn scan(
        &self,
        context: &ExecutionContext<'_>,
        request: &PromptScanRequest,
    ) -> Result<PromptScanOutput, ActionError>;
}
