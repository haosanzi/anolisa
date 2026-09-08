//! Contract tests for the runtime spine, exercised through a fake executor.
//!
//! These pin the guarantees the daemon relies on: validation gates execution,
//! a cancelled invocation never reaches the executor, and every path emits
//! exactly one audit record.

use std::sync::Mutex;

use asc_action_runtime::{
    ActionRuntime, AuditOutcome, AuditRecord, AuditSink, CancellationSignal, CapabilityExecutor,
    ExecutionContext, NeverCancels,
};
use asc_action_types::{ActionError, ActionErrorKind, ActionId, Verdict};

/// Request whose only content is whether validation should accept it.
struct FakeRequest {
    valid: bool,
}

/// Output carrying a fixed verdict for the audit projection.
#[derive(Debug)]
struct FakeOutput {
    verdict: Verdict,
}

/// Executor whose stages return fixed outcomes.
///
/// The runtime skipping a stage is proved by the audit outcome, not a call
/// counter: a skipped execute cannot record its own failure class, and a
/// skipped validate cannot let execute's success through.
struct FakeExecutor {
    execute_should_fail: bool,
}

impl FakeExecutor {
    fn new() -> Self {
        Self {
            execute_should_fail: false,
        }
    }

    fn failing_execute() -> Self {
        Self {
            execute_should_fail: true,
        }
    }
}

impl CapabilityExecutor for FakeExecutor {
    type Request = FakeRequest;
    type Output = FakeOutput;

    fn action_id(&self) -> ActionId {
        ActionId::PromptScan
    }

    fn validate(&self, request: &FakeRequest) -> Result<(), ActionError> {
        if request.valid {
            Ok(())
        } else {
            Err(ActionError::invalid_input("request marked invalid"))
        }
    }

    fn execute(
        &self,
        _ctx: &ExecutionContext<'_>,
        _request: &FakeRequest,
    ) -> Result<FakeOutput, ActionError> {
        if self.execute_should_fail {
            Err(ActionError::dependency_unavailable(
                "backing service is down",
            ))
        } else {
            Ok(FakeOutput {
                verdict: Verdict::Pass,
            })
        }
    }

    fn audit_verdict(&self, output: &FakeOutput) -> Option<Verdict> {
        Some(output.verdict)
    }
}

/// Sink that keeps every record so a test can assert the exact count.
#[derive(Default)]
struct CountingSink {
    records: Mutex<Vec<AuditRecord>>,
}

impl AuditSink for &CountingSink {
    fn record(&self, record: AuditRecord) {
        self.records.lock().expect("sink lock").push(record);
    }
}

impl CountingSink {
    fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().expect("sink lock").clone()
    }
}

/// Cancellation signal fixed to always fire.
struct AlwaysCancelled;

impl CancellationSignal for AlwaysCancelled {
    fn is_cancelled(&self) -> bool {
        true
    }
}

fn context(cancel: &dyn CancellationSignal) -> ExecutionContext<'_> {
    ExecutionContext::new(None, cancel)
}

#[test]
fn happy_path_runs_execute_and_audits_completed() {
    let sink = CountingSink::default();
    let runtime = ActionRuntime::with_sink(FakeExecutor::new(), &sink);
    let never = NeverCancels;

    let output = runtime
        .run(&context(&never), &FakeRequest { valid: true })
        .expect("a valid request completes");

    assert_eq!(output.verdict, Verdict::Pass);
    let records = sink.records();
    assert_eq!(records.len(), 1, "one invocation must emit one record");
    assert_eq!(records[0].action, ActionId::PromptScan);
    assert_eq!(
        records[0].outcome,
        AuditOutcome::Completed {
            verdict: Some(Verdict::Pass)
        }
    );
}

#[test]
fn validation_failure_skips_execute_and_audits_the_failure() {
    let sink = CountingSink::default();
    // A failing execute is wired: if validation did not gate it, the outcome
    // would be DependencyUnavailable rather than the InvalidInput asserted.
    let runtime = ActionRuntime::with_sink(FakeExecutor::failing_execute(), &sink);
    let never = NeverCancels;

    let error = runtime
        .run(&context(&never), &FakeRequest { valid: false })
        .expect_err("an invalid request is rejected");

    assert_eq!(error.kind(), ActionErrorKind::InvalidInput);
    let records = sink.records();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].outcome,
        AuditOutcome::Failed {
            kind: ActionErrorKind::InvalidInput
        }
    );
}

#[test]
fn execute_failure_still_audits_exactly_once() {
    let sink = CountingSink::default();
    let runtime = ActionRuntime::with_sink(FakeExecutor::failing_execute(), &sink);
    let never = NeverCancels;

    let error = runtime
        .run(&context(&never), &FakeRequest { valid: true })
        .expect_err("a downed dependency fails the invocation");

    assert_eq!(error.kind(), ActionErrorKind::DependencyUnavailable);
    let records = sink.records();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].outcome,
        AuditOutcome::Failed {
            kind: ActionErrorKind::DependencyUnavailable
        }
    );
}

#[test]
fn cancelled_before_work_never_validates_or_executes() {
    let sink = CountingSink::default();
    let runtime = ActionRuntime::with_sink(FakeExecutor::new(), &sink);
    let cancelled = AlwaysCancelled;

    let error = runtime
        .run(&context(&cancelled), &FakeRequest { valid: true })
        .expect_err("a cancelled invocation does no work");

    assert_eq!(error.kind(), ActionErrorKind::Cancelled);
    // Even the abandoned invocation is audited, so the log shows the attempt.
    let records = sink.records();
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].outcome,
        AuditOutcome::Failed {
            kind: ActionErrorKind::Cancelled
        }
    );
}
