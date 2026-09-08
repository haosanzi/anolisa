//! Audit records emitted once per invocation, and the sink that receives them.

use asc_action_types::{ActionErrorKind, ActionId, Verdict};

/// How one finished invocation ended.
///
/// Mirrors the `Result` the runtime returns: a completed invocation carries
/// the verdict it reached, a failed one carries only its failure class. The
/// scanned content and the caller-facing message are deliberately absent so
/// an audit log never becomes a second copy of the prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// The Action ran to completion.
    Completed {
        /// Verdict reached, or `None` for an Action that produces no verdict.
        verdict: Option<Verdict>,
    },
    /// The Action could not produce an outcome.
    Failed {
        /// Failure class, copied from the [`ActionError`](asc_action_types::ActionError).
        kind: ActionErrorKind,
    },
}

/// One immutable audit entry for a single invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditRecord {
    /// Action that ran.
    pub action: ActionId,
    /// How the invocation ended.
    pub outcome: AuditOutcome,
}

/// The destination the runtime hands each finished invocation to.
///
/// The runtime emits exactly one record per invocation, on both the success
/// and failure paths, so a sink never has to pair a start with an end or
/// reconcile a missing entry.
pub trait AuditSink {
    /// Records one finished invocation.
    ///
    /// Called on the invocation's own thread; a sink that may block should
    /// hand the record off rather than do slow work inline.
    fn record(&self, record: AuditRecord);
}

/// A sink that discards every record.
///
/// The default until the daemon wires a real audit log, so an executor can
/// run without one. Discarding is explicit rather than the runtime skipping
/// the emit, which keeps the one-record-per-invocation contract intact.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullAuditSink;

impl AuditSink for NullAuditSink {
    fn record(&self, _record: AuditRecord) {}
}
