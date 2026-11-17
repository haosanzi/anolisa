//! Orchestrates direct Cedar candidate generation; a candidate is neither an approval nor an
//! installation into an execution backend.
//!
//! 1. task text + shared schema -> model Cedar draft and model-reported unresolved items.
//! 2. [`TASK_BASE`] + draft -> official parser + canonical absolute-path check + Strict
//!    validation -> Cedar artifact.
//! 3. artifact + raw draft + TTL and hash -> unapproved candidate.
//!
//! A draft rejected as an unsupported feature or a non-canonical path becomes
//! `NeedsClarification` carrying its reasons instead of an error; any other failure aborts the
//! run, and every stage stops at the earliest of the caller deadline, the candidate TTL and
//! [`INTENT_BUDGET`].
//!
//! Tasks and single commands only create new candidates; existing policies are neither read nor
//! rewritten, and permission mapping, intersection and execution stay downstream.

use std::time::{Duration, Instant};

use asc_model_client::provider::ModelProvider;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::policy_validation::prepare_task_text;
use crate::{
    Artifact, HumanGate, INTENT_BUDGET, IntentError, PolicyDraft, PolicyError, TaskInput,
    confirmation_gaps, human_gates, intent_extraction::generate_policy_draft_after,
    launch_view_gaps, point_aliases, prepare_policy, requirement_coverage, runtime_view_gaps,
};

/// Maximum candidate TTL; it is not the lifetime of an issued grant.
pub const MAX_PROPOSAL_TTL: u32 = 1800;
/// Serialization budget for a complete candidate.
pub const MAX_CANDIDATE_BYTES: usize = 512 * 1024;
/// Direct Cedar candidate protocol version.
pub const CANDIDATE_VERSION: &str = "asc.intent.candidate.v1";
/// Prefix of the note listing permits that the launch-time authorization view drops.
pub const LAUNCH_VIEW_NOTE: &str = "LAUNCH VIEW:";
/// Prefix of the note listing point grants that name a link on the generating host.
pub const POINT_ALIAS_NOTE: &str = "POINT ALIAS:";
/// Prefix of the note listing forbids that the runtime protector refuses to lower.
pub const RUNTIME_VIEW_NOTE: &str = "RUNTIME VIEW:";
/// Prefix of the note listing permits that stop for a human before they take effect.
pub const HUMAN_GATE_NOTE: &str = "HUMAN GATE:";
/// Prefix of the note naming which consumers can carry each task requirement.
pub const COVERAGE_NOTE: &str = "COVERAGE:";

/// Launch base every task artifact carries ahead of the model text.
///
/// It is a platform fact, not a task requirement: the Hook launches every command as `bash -c`
/// and how many system directories a launch reads is not predictable, so the read ceiling is the
/// whole filesystem and the actual read limits come from the requirements. The model only sees
/// the task text and cannot know either, so the program writes it and the model never does.
pub const TASK_BASE: &str = r#"// ============================================================
// 基础授权（程序生成，不来自 task）：读取上限与 shell 启动
// 不是安全要求，只让命令能够启动；读取限制与写入范围由下面的要求给出。
// ============================================================

@id("base")
permit(
  principal,
  action == SecCore::Action::"file.read",
  resource is SecCore::File
)
when {
  resource.path == "/" || resource.path like "/*"
};

@id("base.2")
permit(
  principal,
  action == SecCore::Action::"process.spawn",
  resource is SecCore::Process
)
when {
  resource.program == "bash" || resource.program == "/bin/bash" ||
  resource.program == "/usr/bin/bash"
};

"#;

/// Admits a task draft: [`TASK_BASE`] followed by the model text, validated as one revision.
///
/// The raw draft keeps the model text alone; the artifact is what gets published. A task may ask
/// a human to confirm a permission, so this is the one admission that reads an escalation advice.
///
/// # Errors
/// Rejects what [`prepare_policy`] rejects in the model text.
pub fn prepare_task_policy(model_text: &str) -> Result<Artifact, PolicyError> {
    prepare_task_text(&format!("{TASK_BASE}{model_text}"))
}

/// Built from server identity and clock; matching fields in user JSON are never accepted.
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
    /// Fixes the candidate identity and validity window; never renewed automatically.
    ///
    /// # Errors
    /// Rejects invalid identities, timestamp overflow and TTLs outside 1..=1800.
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

#[derive(Serialize)]
struct CandidateContent {
    format_version: &'static str,
    status: &'static str,
    authorization_required: bool,
    #[serde(flatten)]
    context: ProposalContext,
    artifact: Artifact,
    draft: PolicyDraft,
    notes: Vec<String>,
}

/// A candidate that passed Cedar validation but is not approved; the model may still report
/// unresolved requirements.
#[derive(Serialize)]
pub struct CandidatePolicy {
    #[serde(flatten)]
    content: CandidateContent,
    candidate_hash: String,
}

impl CandidatePolicy {
    /// The model policy text.
    pub fn policy_text(&self) -> &str {
        &self.content.artifact.text
    }

    /// Validated Cedar artifact; it does not prove task completeness.
    pub fn artifact(&self) -> &Artifact {
        &self.content.artifact
    }

    /// Requirements the model reported as unresolved; do not hand them to approval as is.
    pub fn unresolved(&self) -> &[String] {
        self.content.draft.unresolved()
    }

    /// Digest over all serialized content except itself; not a signature.
    pub fn candidate_hash(&self) -> &str {
        &self.candidate_hash
    }
}

/// Candidate generation result; no branch means approval or effect.
#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ProposalOutcome {
    /// A valid Cedar candidate that keeps the raw draft and model-reported issues.
    Candidate {
        /// Unapproved candidate.
        candidate: Box<CandidatePolicy>,
    },
    /// The paths or unsupported policy features need rework; there is no approvable candidate.
    NeedsClarification {
        /// The raw model output is still preserved.
        draft: Box<PolicyDraft>,
        /// Reasons reported by the program checks.
        reasons: Vec<String>,
    },
}

/// Cedar derived for one command; not an approval or an effective permission.
#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CommandPolicyOutcome {
    /// Passed the Cedar syntax, path and Strict-type checks; completeness is still unproven.
    Candidate {
        /// Validated Cedar text: the model draft plus the roles a fixed option grammar decides
        /// (currently archive creation), or an empty string to request no permission.
        policy: String,
        /// Known but uncovered parts, such as an unresolved PATH lookup or script behavior; never
        /// treat them as authorized.
        caveats: Vec<String>,
    },
    /// Required information or expressiveness is missing; no partial policy is returned, so it
    /// cannot be mistaken for a complete request.
    NeedsClarification {
        /// Reasons reported by the model or found by the program checks.
        reasons: Vec<String>,
    },
}

/// Maximum model attempts for one command proposal; a single retry repairs the syntax and
/// Strict-typing mistakes models make often enough that failing the hook is worse.
const COMMAND_ATTEMPTS: u8 = 2;

/// Generates Cedar from a hook command/cwd; it reads no base policy and computes no effective
/// permission.
///
/// Reads no file and runs no command. Only a model-reported unresolved item yields no candidate;
/// caveats travel with the candidate. Syntax, Strict-typing and path-literal rejections are
/// retried once with the local reason; unsupported-policy features are never retried. After the
/// retry a syntax or typing failure is an error, while a persistent path rejection becomes a
/// clarification. Validation proves Cedar syntax and types only, never command completeness or
/// minimality.
///
/// The validated draft is then unioned with the file roles a fixed option grammar decides, such
/// as the archive a `tar -czf` creates and the sources it reads; see [`with_fixed_roles`].
///
/// # Errors
/// Returns an error for invalid input or model output, invalid Cedar syntax or types, and
/// timeouts or exceeded limits.
pub fn propose_command(
    provider: &dyn ModelProvider,
    model: &str,
    input: &crate::CommandInput,
    deadline: Instant,
) -> Result<CommandPolicyOutcome, ProposalError> {
    let deadline = deadline.min(Instant::now() + INTENT_BUDGET);
    check_deadline(deadline)?;
    let mut attempt = 1;
    let mut rejection: Option<String> = None;
    loop {
        let response = crate::intent_extraction::generate_command_response(
            provider,
            model,
            input,
            deadline,
            rejection.as_deref(),
        )?;
        if !response.unresolved.is_empty() {
            check_deadline(deadline)?;
            return Ok(CommandPolicyOutcome::NeedsClarification {
                reasons: response.unresolved,
            });
        }
        // An empty policy is the answer for a command with no file, process or network action:
        // it grants nothing, so `prepare_policy` admits it and the caveats stay attached.
        match prepare_policy(&response.policy) {
            Ok(artifact) => {
                check_deadline(deadline)?;
                let (policy, caveats) = with_fixed_roles(input, artifact.text, response.caveats)?;
                return Ok(CommandPolicyOutcome::Candidate { policy, caveats });
            }
            // A rejected draft is retried once with the local reason, so the model can repair a
            // non-canonical path, a wildcard path literal or a schema mismatch instead of the run
            // terminating on it.
            Err(
                error @ (PolicyError::InvalidPath
                | PolicyError::WildcardLiteral
                | PolicyError::Syntax
                | PolicyError::Validation
                | PolicyError::Advice),
            ) if attempt < COMMAND_ATTEMPTS => {
                check_deadline(deadline)?;
                rejection = Some(error.to_string());
                attempt += 1;
            }
            // After the single retry, a persistent path rejection describes the command, not a
            // transient mistake, so it becomes a clarification reason rather than an error.
            Err(
                error @ (PolicyError::InvalidPath
                | PolicyError::WildcardLiteral
                | PolicyError::UnsupportedPolicy),
            ) => {
                check_deadline(deadline)?;
                return Ok(CommandPolicyOutcome::NeedsClarification {
                    reasons: vec![error.to_string()],
                });
            }
            Err(error) => return Err(error.into()),
        }
    }
}

/// Unions a validated model draft with the file roles a fixed option grammar decides.
///
/// A model reads a command as text, so a write that happens inside the program — the archive
/// `tar -czf` creates, the directory pass `-C` selects — is often only described in a caveat, and
/// two probes of the same command produced different drafts. The option grammar is not a guess, so
/// those roles are added here, next to the model text and under the same admission. Any other
/// command keeps the draft unchanged, as does text the analyser cannot read without expanding it.
///
/// A statement naming the archive itself is dropped: the file exists only after the command writes
/// it, and the permission input resolves every literal before the launch, so keeping it would make
/// the launch fail instead of narrowing it. The directory write added here creates the file.
///
/// The union is admitted like a draft: a defect here fails the proposal instead of silently
/// dropping a permission the command needs.
fn with_fixed_roles(
    input: &crate::CommandInput,
    model_text: String,
    caveats: Vec<String>,
) -> Result<(String, Vec<String>), PolicyError> {
    let Some(roles) = crate::command_roles::archive_roles(&input.command, &input.cwd) else {
        return Ok((model_text, caveats));
    };
    let (model_text, dropped) =
        crate::policy_validation::without_named(&model_text, roles.archives())?;
    let text = match model_text.trim_end() {
        "" => roles.cedar(),
        model => format!("{model}\n{}", roles.cedar()),
    };
    let artifact = prepare_policy(&text)?;
    let mut caveats = caveats;
    caveats.push(roles.caveat());
    if dropped > 0 {
        caveats.push(roles.named_caveat(dropped));
    }
    Ok((artifact.text, caveats))
}

/// Orchestration errors carry no task body or model output.
#[derive(Debug, Error)]
pub enum ProposalError {
    /// The server identity or timestamp is invalid.
    #[error("invalid proposal identity, timestamp or TTL")]
    InvalidContext,
    /// The overall deadline or the candidate TTL expired.
    #[error("proposal deadline exceeded")]
    DeadlineExceeded,
    /// The model call or the response wrapper is invalid.
    #[error("proposal generation failed: {0}")]
    Intent(#[from] IntentError),
    /// Real Cedar validation or candidate encoding failed.
    #[error("proposal validation failed: {0}")]
    Policy(#[from] PolicyError),
}

/// First task draft with its local admission; a rejection the model can repair gets one retry.
///
/// A whole task draft fails on one malformed statement often enough that ending the proposal
/// there is worse than one repair round with the local reason.
fn first_task_draft(
    provider: &dyn ModelProvider,
    model: &str,
    task: &TaskInput,
    deadline: Instant,
) -> Result<(PolicyDraft, Result<Artifact, PolicyError>), ProposalError> {
    let draft = generate_policy_draft_after(provider, model, task, deadline, None)?;
    let prepared = prepare_task_policy(draft.policy());
    match prepared {
        Err(
            error @ (PolicyError::InvalidPath
            | PolicyError::WildcardLiteral
            | PolicyError::Syntax
            | PolicyError::Validation
            | PolicyError::Advice),
        ) => {
            check_deadline(deadline)?;
            let retry = generate_policy_draft_after(
                provider,
                model,
                task,
                deadline,
                Some(&error.to_string()),
            )?;
            let prepared = prepare_task_policy(retry.policy());
            Ok((retry, prepared))
        }
        prepared => Ok((draft, prepared)),
    }
}

/// Generates a Cedar candidate directly from a task.
///
/// The model receives the task text only; no file contents are sent and no path metadata is
/// accepted. The draft keeps unresolved items; Strict validation does not prove that task and
/// policy are semantically equivalent. The artifact is [`TASK_BASE`] followed by the draft.
///
/// As for command proposals, a draft rejected for its syntax, Strict typing or a path literal is
/// retried once with the local reason. After that retry a syntax or typing failure is an error,
/// while a persistent path rejection becomes a clarification; unsupported-policy features are
/// never retried.
///
/// A valid draft whose permits test `context` is retried once with that reason, because the
/// launch authorizer reads the same revision without context and would grant those permits
/// nothing. A forbid the runtime protector cannot lower, such as one on `network.use`, is retried
/// the same way, because it fails the whole binding. A confirmation that no other permit covers is
/// retried too (see below). The retry only replaces the first draft when it is valid and has none
/// of these; otherwise the first draft stays the candidate and the findings travel as
/// `LAUNCH VIEW:`, `RUNTIME VIEW:` and `HUMAN GATE:` notes.
///
/// The exact paths the final permits name are then resolved on this host (metadata only; nothing
/// is sent). A point grant on a link authorizes nothing, but it is not retried: the task asked
/// for that name, and the repair is a wider grant only a reviewer may choose. It travels as a
/// `POINT ALIAS:` note instead.
///
/// A permit may also carry an escalation advice, which makes an already granted permission ask a
/// human before each execution. That is only friction when the same action already grants the
/// paths, so a confirmation outside every other permit's grant is reported as a widening: after a
/// retry that still shows one, the revision is marked as not to be published. A `network.use`
/// gate is exempt: the action has no path dimension, so its gate is the task's own request to ask
/// before each use. Admitted gates travel as a `HUMAN GATE:` note with the paths (or the whole
/// network) and the message a prompt will show.
///
/// A `COVERAGE:` note finally names, per requirement `@id`, which consumers can carry its
/// statements. It is derived from statement shape, not from a deployment.
///
/// # Errors
/// Returns no candidate when input, provider, Cedar syntax/types, budgets or the deadline fail.
pub fn propose_task(
    provider: &dyn ModelProvider,
    model: &str,
    task: &TaskInput,
    context: &ProposalContext,
    deadline: Instant,
) -> Result<ProposalOutcome, ProposalError> {
    let deadline = deadline
        .min(context.started + context.ttl)
        .min(Instant::now() + INTENT_BUDGET);
    check_deadline(deadline)?;
    let (mut draft, prepared) = first_task_draft(provider, model, task, deadline)?;
    let mut artifact = match prepared {
        Ok(artifact) => artifact,
        Err(
            error @ (PolicyError::InvalidPath
            | PolicyError::WildcardLiteral
            | PolicyError::UnsupportedPolicy
            | PolicyError::Advice),
        ) => {
            check_deadline(deadline)?;
            return Ok(ProposalOutcome::NeedsClarification {
                draft: Box::new(draft),
                reasons: vec![error.to_string()],
            });
        }
        Err(error) => return Err(error.into()),
    };
    let mut gaps = launch_view_gaps(&artifact.text)?;
    let mut refused = runtime_view_gaps(&artifact.text)?;
    let mut widening = confirmation_gaps(&artifact.text)?;
    if (!gaps.is_empty() || !refused.is_empty() || !widening.is_empty())
        && let Some((retry, repaired)) =
            repair(provider, model, task, deadline, &gaps, &refused, &widening)
    {
        draft = retry;
        artifact = repaired;
        gaps.clear();
        refused.clear();
        widening.clear();
    }
    check_deadline(deadline)?;
    let aliases = point_aliases(&artifact.text, &|path| {
        std::fs::canonicalize(path)
            .ok()?
            .into_os_string()
            .into_string()
            .ok()
    })?;
    let gates = human_gates(&artifact.text)?;
    let coverage = requirement_coverage(&artifact.text)?;
    let notes = candidate_notes(&gaps, &refused, &widening, &aliases, &gates, &coverage);
    let payload = CandidateContent {
        format_version: CANDIDATE_VERSION,
        status: "CANDIDATE",
        authorization_required: true,
        context: context.clone(),
        artifact,
        draft,
        notes,
    };
    let candidate_hash = canonical_hash(&payload)?;
    let candidate = CandidatePolicy {
        content: payload,
        candidate_hash,
    };
    if serde_json::to_vec(&candidate)
        .map_err(|_| PolicyError::Encoding)?
        .len()
        > MAX_CANDIDATE_BYTES - 128
    {
        return Err(PolicyError::TooLarge.into());
    }
    check_deadline(deadline)?;
    Ok(ProposalOutcome::Candidate {
        candidate: Box::new(candidate),
    })
}

/// One repair round for a valid draft that a consumer of this revision would trip over.
///
/// The model gets the local reasons, not the task again. A failed call, a rejected repair or a
/// repair that still carries findings returns `None`: a valid first draft is worth more than none,
/// and the findings then travel as notes instead of silently dropping the revision.
fn repair(
    provider: &dyn ModelProvider,
    model: &str,
    task: &TaskInput,
    deadline: Instant,
    gaps: &[String],
    refused: &[String],
    widening: &[String],
) -> Option<(PolicyDraft, Artifact)> {
    let mut reasons = Vec::new();
    if !gaps.is_empty() {
        reasons.push(format!(
            "the launch authorizer reads no context, so these permits would grant nothing: {}; \
             express permits with resource attributes only and keep context.input.operation for \
             forbids",
            gaps.join("; ")
        ));
    }
    if !refused.is_empty() {
        reasons.push(format!(
            "the runtime protector lowers only bare forbids on file.read or file.write and fails \
             the whole binding otherwise: {}; drop those forbids and grant nothing instead, e.g. \
             no network.use permit",
            refused.join("; ")
        ));
    }
    if !widening.is_empty() {
        reasons.push(format!(
            "a permit may ask for confirmation only on paths another permit of the same action \
             already grants, and these confirmations would widen authorization instead: {}; grant \
             that location in the writable scope first, or drop the confirmation",
            widening.join("; ")
        ));
    }
    let rejection = reasons.join(". ");
    let retry =
        generate_policy_draft_after(provider, model, task, deadline, Some(&rejection)).ok()?;
    let repaired = prepare_task_policy(retry.policy()).ok()?;
    (launch_view_gaps(&repaired.text).is_ok_and(|left| left.is_empty())
        && runtime_view_gaps(&repaired.text).is_ok_and(|left| left.is_empty())
        && confirmation_gaps(&repaired.text).is_ok_and(|left| left.is_empty()))
    .then_some((retry, repaired))
}

/// Fixed review notes plus one note per finding a consumer of this revision would trip over.
fn candidate_notes(
    gaps: &[String],
    refused: &[String],
    widening: &[String],
    aliases: &[String],
    gates: &[HumanGate],
    coverage: &[String],
) -> Vec<String> {
    let mut notes: Vec<String> = vec![
        "CANDIDATE: not approved, not effective; not connected to enforcement.".into(),
        "Cedar Strict validates syntax and types, not task completeness. Review the policy against the original task; unresolved is model-reported, not a completeness proof.".into(),
        "Default deny without a matching permit; forbid takes precedence. A plain permit does not restrict other policies' allows.".into(),
        "file.read is file-content read, not listing names only. There is no implicit workspace or directory grant.".into(),
        "Enforcement must normalize paths, handle links and namespaces, and adjudicate both rename endpoints. Only the task text is sent to the model.".into(),
        "Scope/Binding, approval, expiry revocation and execution remain downstream; executable access does not grant its sub-operations.".into(),
    ];
    if !gaps.is_empty() {
        notes.push(format!(
            "{LAUNCH_VIEW_NOTE} the launch authorizer drops permits that test context, so they \
             authorize no launch: {}.",
            gaps.join("; ")
        ));
    }
    if !refused.is_empty() {
        notes.push(format!(
            "{RUNTIME_VIEW_NOTE} the runtime protector lowers only bare forbids on file.read or \
             file.write, so a Scope on this revision fails: {}.",
            refused.join("; ")
        ));
    }
    if !aliases.is_empty() {
        notes.push(format!(
            "{POINT_ALIAS_NOTE} the authorizer compares canonical paths and the sandbox refuses \
             a point grant on a link, so on this host these grants match nothing and a launch \
             whose request covers them fails: {}. Grant the target as a directory pair or keep \
             the requirement unresolved.",
            aliases.join("; ")
        ));
    }
    if !widening.is_empty() {
        // A confirmation that no other permit covers hands out what the task never asked for, so
        // the export has to say so where a reviewer of the file will read it.
        notes.push(format!(
            "{HUMAN_GATE_NOTE} a permit may ask for confirmation only on a permission the policy \
             already grants, and these confirmations would widen authorization instead: {}; grant \
             that location in the writable scope first, or drop the confirmation. Do not publish \
             this revision.",
            widening.join("; ")
        ));
    } else if !gates.is_empty() {
        // The paths and the wording are what the approval prompt shows, so the reviewer reads the
        // gate here rather than discovering it in the middle of a run.
        let mut note = format!(
            "{HUMAN_GATE_NOTE} these permits stop for confirmation before taking effect. A path \
             listed here is also granted by another permit of the same action, so the gate is \
             friction and not a wider grant; a network.use gate is the whole-network grant itself, \
             so nothing is allowed without confirming it:"
        );
        for gate in gates {
            note.push_str("\n  ");
            note.push_str(&gate.label());
            note.push(' ');
            // A whole-network gate names no path; it is the only gate shape without one.
            if gate.paths.is_empty() {
                note.push_str("network.use");
            } else {
                note.push_str(&gate.paths.join(" "));
            }
            note.push_str(" -- ");
            note.push_str(&gate.message);
        }
        notes.push(note);
    }
    if !coverage.is_empty() {
        // One row per requirement and carrier, aligned, so an exported header shows at a glance
        // which execution boundary carries each requirement.
        let mut note = format!(
            "{COVERAGE_NOTE} who can carry each requirement, from statement shape only:\n  permit \
             -> sandbox + PDP (a permit testing context -> sandbox only; network.use -> PDP);\n  \
             forbid on file.read or file.write -> os-harness (any other forbid -> none).\n  A Scope \
             still has to apply it; a requirement without statements is not listed."
        );
        for row in coverage {
            note.push_str("\n  ");
            note.push_str(row);
        }
        notes.push(note);
    }
    notes
}

fn check_deadline(deadline: Instant) -> Result<(), ProposalError> {
    if Instant::now() >= deadline {
        Err(ProposalError::DeadlineExceeded)
    } else {
        Ok(())
    }
}

fn stable_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn canonical_hash(value: &impl Serialize) -> Result<String, PolicyError> {
    fn sort(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(fields) => {
                fields.sort_keys();
                for value in fields.values_mut() {
                    sort(value);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    sort(value);
                }
            }
            _ => {}
        }
    }
    let mut value = serde_json::to_value(value).map_err(|_| PolicyError::Encoding)?;
    sort(&mut value);
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&value).map_err(|_| PolicyError::Encoding)?)
    ))
}
