//! Execution layer for `AgentSecCore` Actions.
//!
//! Sits between the daemon boundary, which owns decoding and authorization,
//! and a capability, which owns detection. It gives every Action the same
//! spine so a capability only writes the parts that differ:
//!
//! - [`CapabilityExecutor`] is the port a capability implements: validate a
//!   decoded request, then execute it to a business outcome.
//! - [`ExecutionContext`] carries the per-invocation limits (deadline and a
//!   cancellation signal) so a long-running capability can bail out instead
//!   of billing a caller who has already gone away.
//! - [`ActionRuntime`] runs the fixed sequence — reject-if-cancelled,
//!   validate, execute — and emits exactly one [`AuditRecord`] whichever way
//!   the invocation ended, so an audit log never has to reconcile partial or
//!   missing entries.
//!
//! Registration is closed: one runtime binds one executor, matching the
//! daemon's closed method table. A registry keyed by a runtime action id is
//! only worth adding once there is a second Action to dispatch between.
#![forbid(unsafe_code)]

pub mod audit;
pub mod context;
pub mod executor;
pub mod runtime;

pub use audit::{AuditOutcome, AuditRecord, AuditSink, NullAuditSink};
pub use context::{CancellationSignal, ExecutionContext, NeverCancels};
pub use executor::CapabilityExecutor;
pub use runtime::ActionRuntime;
