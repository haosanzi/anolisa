//! The fixed sequence every Action invocation runs through.

use asc_action_types::ActionError;

use crate::audit::{AuditOutcome, AuditRecord, AuditSink, NullAuditSink};
use crate::context::ExecutionContext;
use crate::executor::CapabilityExecutor;

/// Drives one capability through the sequence every Action shares:
/// reject-if-cancelled, validate, execute, then audit exactly once.
///
/// Registration is closed on purpose: one runtime binds one executor, which
/// is all the daemon's closed method table needs to dispatch. The audit sink
/// defaults to [`NullAuditSink`] so an executor runs without a log until one
/// is wired.
pub struct ActionRuntime<E, S = NullAuditSink> {
    executor: E,
    sink: S,
}

impl<E> ActionRuntime<E> {
    /// Builds a runtime that discards audit records.
    pub fn new(executor: E) -> Self {
        Self {
            executor,
            sink: NullAuditSink,
        }
    }
}

impl<E, S> ActionRuntime<E, S>
where
    E: CapabilityExecutor,
    S: AuditSink,
{
    /// Builds a runtime that reports every finished invocation to `sink`.
    pub fn with_sink(executor: E, sink: S) -> Self {
        Self { executor, sink }
    }

    /// Runs one request end to end.
    ///
    /// Rejects a cancelled invocation before any work, validates, then
    /// executes, checking for cancellation between stages so an abandoned
    /// request stops promptly. Emits exactly one [`AuditRecord`] before
    /// returning, on both the success and failure paths.
    ///
    /// # Errors
    /// Propagates [`validate`](CapabilityExecutor::validate) and
    /// [`execute`](CapabilityExecutor::execute) failures, and returns
    /// [`ActionError::cancelled`] when the invocation was already abandoned
    /// at a checkpoint.
    pub fn run(
        &self,
        ctx: &ExecutionContext<'_>,
        request: &E::Request,
    ) -> Result<E::Output, ActionError> {
        let outcome = self.run_stages(ctx, request);
        let record = AuditRecord {
            action: self.executor.action_id(),
            outcome: match &outcome {
                Ok(output) => AuditOutcome::Completed {
                    verdict: self.executor.audit_verdict(output),
                },
                Err(error) => AuditOutcome::Failed { kind: error.kind() },
            },
        };
        self.sink.record(record);
        outcome
    }

    /// Runs validate then execute, short-circuiting on the first failure.
    ///
    /// Kept separate from [`run`](Self::run) so audit emission wraps every
    /// return path without each early return having to remember to log.
    fn run_stages(
        &self,
        ctx: &ExecutionContext<'_>,
        request: &E::Request,
    ) -> Result<E::Output, ActionError> {
        ctx.checkpoint()?;
        self.executor.validate(request)?;
        ctx.checkpoint()?;
        self.executor.execute(ctx, request)
    }
}
