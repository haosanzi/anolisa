//! The process-owned capability inventory. Handlers never assemble runtimes or sinks.
use asc_action_runtime::{ActionRuntime, Finalizer};
use asc_action_types::ActionId;
use asc_capability_code_scan::{CodeScanAuditProjector, CodeScanExecutor};
use asc_capability_prompt_scan::{
    CachingScannerProvider, PromptScanAuditProjector, PromptScanExecutor,
};
use asc_daemon_core::ActionService;
use std::sync::Arc;

/// Composes every implemented scan with the same required finalization infrastructure.
#[must_use]
pub fn scan_application(finalizer: Finalizer) -> Arc<ActionService> {
    // The finalizer shares one sink set across capabilities; cloning it forks
    // the Arc handles, not the sinks, so both runtimes finalize identically.
    Arc::new(ActionService::new(
        ActionRuntime::new(
            ActionId::CodeScan,
            CodeScanExecutor,
            CodeScanAuditProjector,
            finalizer.clone(),
        ),
        ActionRuntime::new(
            ActionId::PromptScan,
            // The provider builds scanners lazily per mode, so daemon startup
            // never depends on model-service configuration and the rule-set
            // compilation cost is paid once per mode, not per request.
            PromptScanExecutor::new(Arc::new(CachingScannerProvider::default())),
            PromptScanAuditProjector,
            finalizer,
        ),
    ))
}
