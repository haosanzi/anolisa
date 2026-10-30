//! Generate pending Cedar and a same-source permission summary from a task and bounded snapshot.
//!
//! [`propose_task`] combines general semantic extraction, exact resource resolution
//! and read-only compilation without prior approval. The model receives only task
//! text; evidence proves textual presence, not semantic accuracy or authorization.
//! Callers supply identity, clocks and materials; downstream services own trusted
//! approval, OS object verification, publication and enforcement.
//! Use [`interpret_task`] for standalone semantic analysis.
//!
//! # Examples
//!
//! Replay a matching offline response without contacting a model service:
//!
//! ```
//! use std::time::Instant;
//! use asc_intent::{INTENT_BUDGET, InterpretOutcome, TaskInput, interpret_task};
//! use asc_model_client::provider::FakeProvider;
//!
//! let task = TaskInput {
//!     source_id: "task-1".into(),
//!     text: "Write a poem".into(),
//! };
//! let provider = FakeProvider::new(r#"{
//!   "goal": "Write a poem",
//!   "resources": {"read": [], "write": [], "egress": []},
//!   "read_selectors": [], "requested_actions": [], "prohibitions": [], "assumptions": [],
//!   "observed_only": [], "unresolved": [], "external_influences": [],
//!   "evidence": [{"field": "/goal", "source_id": "task-1", "quote": "Write a poem"}]
//! }"#.into());
//! let result = interpret_task(&provider, "fixture", &task, Instant::now() + INTENT_BUDGET)?;
//! assert!(matches!(result, InterpretOutcome::Draft { .. }));
//! # Ok::<(), asc_intent::IntentError>(())
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod evidence;
mod interpreter;
mod policy;
mod proposal;
mod resolve;

pub use evidence::{EvidenceError, QuoteReference, TextEvidence, resolve_text_evidence};
pub use interpreter::{
    Action, INTENT_BUDGET, IntentError, IntentIssue, InterpretOutcome, TaskInput, TaskIntentDraft,
    interpret_task,
};
pub use policy::{CEDAR_SCHEMA, CandidatePolicy, MAX_CANDIDATE_BYTES, PolicyError};
pub use proposal::{
    MAX_PROPOSAL_TTL, ProposalContext, ProposalError, ProposalOutcome, RejectionReason,
    propose_task,
};
pub use resolve::{
    MAX_MATERIAL_BYTES, MAX_OBJECTS, Material, MaterialVersion, ResourceIssue, ResourceIssueKind,
    ResourceScope, ResourceSnapshot, ScopeKind, SnapshotError, SnapshotObject, SnapshotSource,
};
