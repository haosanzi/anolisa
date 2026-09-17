//! Shared test fixtures for daemon handler unit tests.

use std::sync::Arc;

use asc_action_runtime::{
    ActionRuntime, CapabilityExecutor, SecurityEventSink, testing::audit_finalizer,
};
use asc_action_types::{ActionId, CodeScanRequest, PromptScanRequest};
use asc_capability_code_scan::{CodeScanAuditProjector, CodeScanExecutor};
use asc_capability_prompt_scan::{PromptScanAuditProjector, PromptScanExecutor};
use asc_daemon_core::ActionService;
use asc_security_events::SecurityEvent;

/// Sink that discards all security events.
pub struct NoopSink;

impl SecurityEventSink for NoopSink {
    fn write(&self, _: &SecurityEvent) {}
}

/// Sink that records all security events for later inspection.
#[derive(Default)]
pub struct RecordingSink(pub std::sync::Mutex<Vec<SecurityEvent>>);

impl SecurityEventSink for RecordingSink {
    fn write(&self, event: &SecurityEvent) {
        self.0.lock().expect("sink lock").push(event.clone());
    }
}

/// Builds an `ActionService` with real scan capabilities and the given event sink.
pub fn action_service_with_sink(sink: Arc<dyn SecurityEventSink>) -> Arc<ActionService> {
    action_service_with_code_executor(sink, CodeScanExecutor)
}

/// Builds an `ActionService` with a custom code-scan executor.
pub fn action_service_with_code_executor<E>(
    sink: Arc<dyn SecurityEventSink>,
    code_executor: E,
) -> Arc<ActionService>
where
    E: CapabilityExecutor<Request = CodeScanRequest> + 'static,
{
    Arc::new(ActionService::new(
        ActionRuntime::new(
            ActionId::CodeScan,
            code_executor,
            CodeScanAuditProjector,
            audit_finalizer(sink.clone()),
        ),
        ActionRuntime::new(
            ActionId::PromptScan,
            PromptScanExecutor::default(),
            PromptScanAuditProjector,
            audit_finalizer(sink),
        ),
    ))
}

/// Builds an `ActionService` with a custom prompt-scan executor.
pub fn action_service_with_prompt_executor<E>(
    sink: Arc<dyn SecurityEventSink>,
    prompt_executor: E,
) -> Arc<ActionService>
where
    E: CapabilityExecutor<Request = PromptScanRequest> + 'static,
{
    Arc::new(ActionService::new(
        ActionRuntime::new(
            ActionId::CodeScan,
            CodeScanExecutor,
            CodeScanAuditProjector,
            audit_finalizer(sink.clone()),
        ),
        ActionRuntime::new(
            ActionId::PromptScan,
            prompt_executor,
            PromptScanAuditProjector,
            audit_finalizer(sink),
        ),
    ))
}
