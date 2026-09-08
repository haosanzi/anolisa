//! Stable Action contracts for the `AgentSecCore` daemon.
//!
//! This crate holds data contracts only. Execution, authorization, and the
//! scan engine live in higher-level crates. Rust types are canonical; serde
//! JSON is the wire representation.
//!
//! Two contracts hold across every Action:
//!
//! - Execution status and business outcome are separate. A completed Action
//!   returns its own output type carrying a [`Verdict`]; one that could not run
//!   returns an [`ActionError`]. No caller has to distinguish "the scanner says
//!   this is dangerous" from "the scanner could not look".
//! - Requests are decoded strictly. Unknown fields are rejected, and a field
//!   the requested mode cannot act on is a validation failure rather than a
//!   silent no-op.

#![forbid(unsafe_code)]

pub mod action;
pub mod prompt_scan;
pub mod result;

pub use action::ActionId;
pub use prompt_scan::{
    ConversationTurn, Finding, LayerFailure, LayerOutcome, MAX_SOURCE_BYTES, ModelId,
    PromptScanOutput, PromptScanRequest, RiskLevel, ScanMode, ThreatType, TurnRole,
};
pub use result::{ActionError, ActionErrorKind, Verdict};
