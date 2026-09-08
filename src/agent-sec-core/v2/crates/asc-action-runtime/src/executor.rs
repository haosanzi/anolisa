//! The port a capability implements to be driven by the runtime.

use asc_action_types::{ActionError, ActionId, Verdict};

use crate::context::ExecutionContext;

/// The behaviour one Action capability must provide.
///
/// Splits a request's handling into the two stages the runtime sequences:
/// a cheap [`validate`](Self::validate) that rejects unusable input before
/// any work, and an [`execute`](Self::execute) that produces the outcome.
/// Decoding, authorization, and encoding are the daemon boundary's job and
/// deliberately absent here, so a capability never re-implements them.
pub trait CapabilityExecutor {
    /// Decoded request this capability accepts.
    type Request;

    /// Business result produced on a completed invocation.
    type Output;

    /// Returns the Action this executor serves.
    ///
    /// Recorded in the audit entry so the log names the Action even when the
    /// invocation failed before producing an output.
    fn action_id(&self) -> ActionId;

    /// Rejects a request that cannot be acted on, before any work starts.
    ///
    /// Runs first so a malformed request costs a cheap check rather than a
    /// model round trip. A field the request cannot act on is a failure here,
    /// not something to ignore.
    ///
    /// # Errors
    /// Returns an [`ActionError`], normally [`ActionError::invalid_input`],
    /// naming what makes the request unusable.
    fn validate(&self, request: &Self::Request) -> Result<(), ActionError>;

    /// Runs a validated request to its business outcome.
    ///
    /// Called only after [`validate`](Self::validate) has passed. May block
    /// on a backing service, so implementations should consult `ctx` around
    /// interruptible work and stop early once it reports the invocation gone.
    ///
    /// # Errors
    /// Returns an [`ActionError`] describing why no outcome could be produced,
    /// classified so the daemon can project it onto a transport error code.
    fn execute(
        &self,
        ctx: &ExecutionContext<'_>,
        request: &Self::Request,
    ) -> Result<Self::Output, ActionError>;

    /// Returns the verdict an output settled on, for the audit record.
    ///
    /// The executor owns its output type, so it projects the audit outcome
    /// itself: this keeps the runtime free of any per-capability output shape
    /// and the contracts crate free of behaviour. Returns `None` for an
    /// Action that produces no verdict.
    fn audit_verdict(&self, output: &Self::Output) -> Option<Verdict>;
}
