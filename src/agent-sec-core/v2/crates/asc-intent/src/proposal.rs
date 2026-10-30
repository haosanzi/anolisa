//! Combine extraction, resource resolution and read-only compilation into a pending candidate.

use asc_policy_types::filesystem::FilesystemPermission;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use asc_model_client::provider::ModelProvider;
use serde::Serialize;
use thiserror::Error;

use crate::policy::{CandidatePolicy, PolicyError, compile_initial_candidate};
use crate::resolve::{
    ResolvedDirectory, ResolvedRead, ResourceIssue, ResourceSnapshot, resolve, resolve_directories,
    stable_id,
};
use crate::{
    Action, IntentError, IntentIssue, InterpretOutcome, TaskInput, TaskIntentDraft, interpret_task,
};

/// Maximum proposal TTL in seconds, also used by the demo; not an issued lease.
pub const MAX_PROPOSAL_TTL: u32 = 1800;

/// Context built from the caller's clock and request identity, never deserialized from user JSON.
#[derive(Clone, Serialize)]
pub struct ProposalContext {
    pub(crate) task_id: String,
    pub(crate) created_at: i64,
    pub(crate) expires_at: i64,
    #[serde(skip)]
    started: Instant,
    #[serde(skip)]
    ttl: Duration,
}

impl ProposalContext {
    /// Fix the candidate identity and expiry without automatic renewal before approval.
    ///
    /// # Errors
    /// Returns [`ProposalError::InvalidContext`] for an invalid ID, nonpositive or
    /// overflowing timestamp, or TTL outside 1..=1800 seconds.
    pub fn new(task_id: String, created_at: i64, ttl: u32) -> Result<Self, ProposalError> {
        let expires_at = created_at
            .checked_add(i64::from(ttl))
            .ok_or(ProposalError::InvalidContext)?;
        if !stable_id(&task_id) || created_at <= 0 || !(1..=MAX_PROPOSAL_TTL).contains(&ttl) {
            return Err(ProposalError::InvalidContext);
        }
        Ok(Self {
            task_id,
            created_at,
            expires_at,
            started: Instant::now(),
            ttl: Duration::from_secs(u64::from(ttl)),
        })
    }
}

pub(crate) struct ResolvedIntent {
    pub(crate) draft: TaskIntentDraft,
    pub(crate) snapshot: ResourceSnapshot,
    pub(crate) context: ProposalContext,
    pub(crate) reads: Vec<ResolvedRead>,
    pub(crate) directories: Vec<ResolvedDirectory>,
}

/// Proposal result; only the candidate variant contains Cedar for review.
#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ProposalOutcome {
    /// Deterministically validated, but neither approved nor effective.
    Candidate {
        /// Complete candidate retaining the task, evidence, bindings and permission summary.
        candidate: Box<CandidatePolicy>,
    },
    /// Requirements or resources need clarification without discarding original semantics.
    NeedsClarification {
        /// Draft with validated evidence.
        draft: Box<TaskIntentDraft>,
        /// Conflicts, unresolved requirements or missing read scope.
        intent_issues: Vec<IntentIssue>,
        /// Missing or ambiguous resources and selectable alternatives.
        resource_issues: Vec<ResourceIssue>,
    },
    /// The template cannot satisfy the explicit request; no partial candidate is generated.
    Rejected {
        /// Original draft including unsupported requests.
        draft: Box<TaskIntentDraft>,
        /// Reason from the closed rejection vocabulary.
        reason: RejectionReason,
    },
}

/// Rejection reasons for the current read-only template.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// The user explicitly requested effects or output destinations beyond read-only access.
    UnsupportedRequest,
    /// The selected backend cannot enforce the exact permission contract; no fallback is allowed.
    UnsupportedBackend,
}

impl ProposalOutcome {
    /// Check trusted adapter capabilities; discard unsupported candidates while retaining the draft.
    /// Capability matching is neither approval, OS object verification nor policy deployment.
    #[must_use]
    pub fn require_backend(self, supported: &BTreeSet<FilesystemPermission>) -> Self {
        match self {
            Self::Candidate { candidate }
                if !candidate.required_permissions().is_subset(supported) =>
            {
                Self::Rejected {
                    draft: Box::new(candidate.into_draft()),
                    reason: RejectionReason::UnsupportedBackend,
                }
            }
            outcome => outcome,
        }
    }

    /// Development entrypoint exit code; zero means a candidate exists, never approval.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Candidate { .. } => 0,
            Self::NeedsClarification { .. } => 2,
            Self::Rejected { .. } => 3,
        }
    }
}

/// Proposal failures that omit task text and file names.
#[derive(Debug, Error)]
pub enum ProposalError {
    /// The caller's identity, timestamp or TTL is invalid.
    #[error("invalid proposal identity, timestamp or TTL")]
    InvalidContext,
    /// The overall budget or candidate lifetime has expired.
    #[error("proposal deadline exceeded")]
    DeadlineExceeded,
    /// Typed extraction failure; no fallback to a previous candidate.
    #[error("proposal extraction failed: {0}")]
    Intent(#[from] IntentError),
    /// Compilation or official Cedar validation failed.
    #[error("proposal compilation failed: {0}")]
    Policy(#[from] PolicyError),
}

/// Propose from a task and bounded materials without prior approval or manual entity bindings.
///
/// Only the task reaches the model; snapshot contents are not sent to the provider.
/// The caller supplies a valid identity and clock. Downstream services remain
/// responsible for OS object verification, trusted approval and publication.
///
/// # Errors
/// Returns typed errors for invalid input, model or compilation failures, and
/// expired deadlines; partial candidates are never returned.
pub fn propose_task(
    provider: &dyn ModelProvider,
    model: &str,
    task: &TaskInput,
    snapshot: &ResourceSnapshot,
    context: &ProposalContext,
    deadline: Instant,
) -> Result<ProposalOutcome, ProposalError> {
    let deadline = deadline.min(context.started + context.ttl);
    check_deadline(deadline)?;
    if snapshot.task_id != context.task_id {
        return Err(ProposalError::InvalidContext);
    }
    let (draft, intent_issues) = match interpret_task(provider, model, task, deadline)? {
        InterpretOutcome::Draft { draft } => (draft, Vec::new()),
        InterpretOutcome::NeedsClarification { draft, reasons } => (draft, reasons),
    };
    // Clarifying a request that can never become a read-only candidate only delays the
    // rejection and makes the outcome depend on how many unresolved notes a model adds.
    if draft.requested_actions().iter().any(|action| {
        !matches!(
            action,
            Action::Read | Action::DirectoryListing | Action::Metadata
        )
    }) || draft.has_unsupported_resources()
    {
        return Ok(ProposalOutcome::Rejected {
            draft: Box::new(draft),
            reason: RejectionReason::UnsupportedRequest,
        });
    }
    if !intent_issues.is_empty() {
        return Ok(ProposalOutcome::NeedsClarification {
            draft: Box::new(draft),
            intent_issues,
            resource_issues: Vec::new(),
        });
    }
    let directory_permissions: BTreeSet<_> = draft
        .requested_actions()
        .iter()
        .filter_map(|action| match action {
            Action::DirectoryListing => Some(FilesystemPermission::List),
            Action::Metadata => Some(FilesystemPermission::Metadata),
            _ => None,
        })
        .collect();
    // Without per-resource action mapping, mixed requests would widen access through a cross product.
    if !directory_permissions.is_empty() && draft.requested_actions().contains(&Action::Read) {
        return Ok(ProposalOutcome::Rejected {
            draft: Box::new(draft),
            reason: RejectionReason::UnsupportedRequest,
        });
    }
    let requests_read =
        draft.requested_actions().contains(&Action::Read) || !directory_permissions.is_empty();
    let has_read_scope = !draft.read_resources().is_empty();
    if requests_read != has_read_scope {
        return Ok(ProposalOutcome::NeedsClarification {
            draft: Box::new(draft),
            intent_issues: vec![IntentIssue::MissingReadScope],
            resource_issues: Vec::new(),
        });
    }
    let resolved = if directory_permissions.is_empty() {
        resolve(&draft, snapshot).map(|reads| (reads, Vec::new()))
    } else {
        resolve_directories(&draft, snapshot, &directory_permissions).map(|dirs| (Vec::new(), dirs))
    };
    let (reads, directories) = match resolved {
        Ok(resolved) => resolved,
        Err(resource_issues) => {
            return Ok(ProposalOutcome::NeedsClarification {
                draft: Box::new(draft),
                intent_issues: Vec::new(),
                resource_issues,
            });
        }
    };
    check_deadline(deadline)?;
    let candidate = compile_initial_candidate(ResolvedIntent {
        draft,
        snapshot: snapshot.clone(),
        context: context.clone(),
        reads,
        directories,
    })?;
    check_deadline(deadline)?;
    Ok(ProposalOutcome::Candidate {
        candidate: Box::new(candidate),
    })
}

fn check_deadline(deadline: Instant) -> Result<(), ProposalError> {
    if Instant::now() >= deadline {
        Err(ProposalError::DeadlineExceeded)
    } else {
        Ok(())
    }
}
