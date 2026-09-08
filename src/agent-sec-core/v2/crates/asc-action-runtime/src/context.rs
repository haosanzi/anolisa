//! Per-invocation execution limits.

use std::time::Instant;

use asc_action_types::ActionError;

/// A source that reports whether the current invocation has been abandoned.
///
/// The runtime never blocks on this; a capability polls it around work it can
/// interrupt. The daemon dispatch layer supplies the concrete signal, so this
/// crate stays free of any transport dependency.
pub trait CancellationSignal {
    /// Returns whether the invocation should stop as soon as it can.
    fn is_cancelled(&self) -> bool;
}

/// A signal that never fires.
///
/// For callers with no cancellation source, such as tests and in-process
/// one-shot use, so [`ExecutionContext`] always has a signal to borrow.
#[derive(Debug, Default, Clone, Copy)]
pub struct NeverCancels;

impl CancellationSignal for NeverCancels {
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// The limits one invocation must respect, handed to a capability's
/// [`execute`](crate::CapabilityExecutor::execute).
///
/// Borrows its cancellation signal for the invocation's lifetime rather than
/// owning it, so the dispatch layer keeps a single source of truth for
/// whether the peer is still waiting.
pub struct ExecutionContext<'a> {
    deadline: Option<Instant>,
    cancel: &'a dyn CancellationSignal,
}

impl<'a> ExecutionContext<'a> {
    /// Builds a context from an optional deadline and a cancellation signal.
    pub fn new(deadline: Option<Instant>, cancel: &'a dyn CancellationSignal) -> Self {
        Self { deadline, cancel }
    }

    /// Returns the instant past which the result is no longer wanted.
    pub const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Returns whether the caller has withdrawn the request.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Returns whether the deadline has already elapsed.
    ///
    /// A context with no deadline never expires.
    pub fn is_expired(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// Fails when the invocation should no longer run.
    ///
    /// Meant to be called before and between expensive stages so an abandoned
    /// request stops promptly rather than running to completion for no reader.
    ///
    /// # Errors
    /// Returns [`ActionError::cancelled`] when the caller has withdrawn the
    /// request or the deadline has elapsed.
    pub fn checkpoint(&self) -> Result<(), ActionError> {
        if self.is_cancelled() {
            return Err(ActionError::cancelled(
                "invocation was cancelled by the caller",
            ));
        }
        if self.is_expired() {
            return Err(ActionError::cancelled(
                "invocation deadline elapsed before completion",
            ));
        }
        Ok(())
    }
}
