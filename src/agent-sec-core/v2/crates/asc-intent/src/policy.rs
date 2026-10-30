//! Generate Cedar and a permission summary from one resolved scope, then validate strictly.
//! Candidates retain provenance but imply no approval, publication or OS object binding.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr as _;

use cedar_policy::{
    Effect, EntityId, EntityTypeName, EntityUid, PolicySet, Schema, ValidationMode, Validator,
};
use serde::Serialize;
use thiserror::Error;

use crate::TaskIntentDraft;
use crate::proposal::{ProposalContext, ResolvedIntent};
use crate::resolve::{
    ResolvedDirectory, ResolvedRead, ResourceSnapshot, canonical_hash, digest_bytes,
};
use asc_policy_types::filesystem::FilesystemPermission;

/// Task permits require a trusted `Agent.task` and matching `context.authorization`.
/// These optional fields preserve non-task requests, but their absence grants no
/// task access. Entity IDs bind exact snapshot objects; paths alone do not.
pub const CEDAR_SCHEMA: &str = include_str!("../../asc-policy-cedar/schema/seccore.cedarschema");

/// Side effects the audited initial template always forbids.
const FORBIDDEN_ACTIONS: [&str; 9] = [
    "filesystem.write",
    "filesystem.create",
    "filesystem.delete",
    "filesystem.rename",
    "filesystem.chmod",
    "filesystem.execute",
    "process.spawn",
    "network.use",
    "tool.invoke",
];

/// Message a PEP shows when the task-wide forbid rule stops an operation.
const DENY_MESSAGE: &str = "Operation outside the task authorization scope. File-content reads, \
directory listing and metadata inspection are independent permissions and cannot substitute for \
or widen one another. File changes, execution, network access and tool invocation require separate authorization.";

/// Maximum compact JSON size of a complete candidate, including its summary and Cedar.
pub const MAX_CANDIDATE_BYTES: usize = 512 * 1024;

#[derive(Serialize)]
struct PermissionScope {
    #[serde(flatten)]
    context: ProposalContext,
    contract_revision: u32,
    binding_revision: u32,
    reads: Vec<ResolvedRead>,
    directories: Vec<ResolvedDirectory>,
    filesystem_contract: &'static str,
    required_permissions: BTreeSet<FilesystemPermission>,
    forbidden_actions: Vec<&'static str>,
}

#[derive(Serialize)]
struct CandidateContent {
    format_version: &'static str,
    kind: &'static str,
    status: &'static str,
    authorization_required: bool,
    profile: &'static str,
    schema_sha256: String,
    draft: TaskIntentDraft,
    binding_snapshot: ResourceSnapshot,
    binding_snapshot_digest: String,
    #[serde(flatten)]
    permissions: PermissionScope,
    rule_sources: BTreeMap<String, Vec<String>>,
    back_translation: Vec<String>,
    policy_set: String,
}

/// Pending candidate that passed parsing, strict validation and scope checks.
///
/// Private fields prevent unchecked construction; the hash covers all serialized
/// content except the hash itself.
#[derive(Serialize)]
pub struct CandidatePolicy {
    #[serde(flatten)]
    content: CandidateContent,
    candidate_hash: String,
}

impl CandidatePolicy {
    /// Exact backend permissions; content reads cannot substitute for listing or metadata.
    pub fn required_permissions(&self) -> &BTreeSet<FilesystemPermission> {
        &self.content.permissions.required_permissions
    }

    pub(crate) fn into_draft(self) -> TaskIntentDraft {
        self.content.draft
    }

    /// Cedar policy text that parsed and validated against [`CEDAR_SCHEMA`].
    pub fn policy_set(&self) -> &str {
        &self.content.policy_set
    }

    /// Content hash over the candidate metadata and its Cedar text.
    pub fn candidate_hash(&self) -> &str {
        &self.candidate_hash
    }
}

/// Candidate generation failures that omit Cedar text and resource names.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The complete candidate exceeds the handoff size limit.
    #[error("candidate exceeds its size limit")]
    TooLarge,
    /// The candidate could not be serialized canonically.
    #[error("candidate encoding failed")]
    Encoding,
    /// Generated text failed official Cedar parsing.
    #[error("generated candidate is not valid Cedar")]
    Syntax,
    /// Generated text contradicts the shared schema under strict validation.
    #[error("generated candidate failed Cedar schema validation")]
    Schema,
    /// Parsed rules lost a required annotation or no longer match the template.
    #[error("generated candidate lost required rule annotations or identifiers")]
    RuleShape,
}

pub(crate) fn compile_initial_candidate(
    intent: ResolvedIntent,
) -> Result<CandidatePolicy, PolicyError> {
    let profile = if intent.directories.is_empty() {
        "readonly@1"
    } else {
        "directory-inspection@1"
    };
    let mut required_permissions = BTreeSet::new();
    let mut forbidden_actions = FORBIDDEN_ACTIONS.to_vec();
    if !intent.reads.is_empty() {
        required_permissions.insert(FilesystemPermission::Read);
    }
    for directory in &intent.directories {
        required_permissions.extend(&directory.permissions);
    }
    if !intent.directories.is_empty() {
        forbidden_actions.push("filesystem.read");
    }
    let permissions = PermissionScope {
        context: intent.context,
        contract_revision: 1,
        binding_revision: 1,
        reads: intent.reads,
        directories: intent.directories,
        filesystem_contract: "filesystem-access@1",
        required_permissions,
        forbidden_actions,
    };
    let task = entity_uid("AgentSec::Task", &permissions.context.task_id)?;
    let mut rules = Vec::with_capacity(permissions.reads.len() + 1);
    let mut rule_sources = BTreeMap::new();
    for read in &permissions.reads {
        let rule_id = format!(
            "{}-read-{}",
            permissions.context.task_id, read.object.entity_id
        );
        rules.push(read_permit(
            &rule_id,
            &task,
            &entity_uid("AgentSec::FilesystemResource", &read.object.entity_id)?,
            &permissions,
        ));
        rule_sources.insert(rule_id, read.requested_as.iter().cloned().collect());
    }
    for directory in &permissions.directories {
        for permission in &directory.permissions {
            let rule_id = format!(
                "{}-{}-{}",
                permissions.context.task_id,
                permission.action(),
                directory.entity_id
            );
            let resource = entity_uid("AgentSec::FilesystemResource", &directory.entity_id)?;
            rules.push(directory_permit(
                &rule_id,
                &task,
                &resource,
                *permission,
                &permissions,
            ));
            rule_sources.insert(rule_id, directory.requested_as.iter().cloned().collect());
        }
    }
    let deny_rule_id = format!("{}-deny-side-effects", permissions.context.task_id);
    rules.push(side_effect_forbid(
        &deny_rule_id,
        &task,
        &permissions.forbidden_actions,
    ));
    rule_sources.insert(deny_rule_id, vec![profile.to_owned()]);
    let policy_set = rules.join("\n");
    verify(&policy_set, &rule_sources)?;
    let back_translation = summarize(&permissions, &intent.draft);
    let content = CandidateContent {
        format_version: "asc.intent.candidate.v1",
        kind: "initial",
        status: "CANDIDATE",
        authorization_required: true,
        profile,
        schema_sha256: digest_bytes(CEDAR_SCHEMA.as_bytes()),
        draft: intent.draft,
        binding_snapshot_digest: intent.snapshot.digest().to_owned(),
        binding_snapshot: intent.snapshot,
        permissions,
        rule_sources,
        back_translation,
        policy_set,
    };
    let candidate_hash = canonical_hash(&content).map_err(|_| PolicyError::Encoding)?;
    let candidate = CandidatePolicy {
        content,
        candidate_hash,
    };
    if serde_json::to_vec(&candidate)
        .map_err(|_| PolicyError::Encoding)?
        .len()
        > MAX_CANDIDATE_BYTES
    {
        return Err(PolicyError::TooLarge);
    }
    Ok(candidate)
}

fn summarize(scope: &PermissionScope, draft: &TaskIntentDraft) -> Vec<String> {
    let mut lines = vec![
        "Pending approval; not effective. This is the requested scope, not existing permissions."
            .into(),
        format!("Task goal (not enforced): {:?}", draft.goal()),
        format!(
            "Only task {:?}, contract revision {}, binding revision {}, until Unix second {}; \
             expiry does not refresh automatically.",
            scope.context.task_id,
            scope.contract_revision,
            scope.binding_revision,
            scope.context.expires_at
        ),
    ];
    for read in &scope.reads {
        lines.push(format!(
            "Request read-only access to {:?}/{:?} ({:?}, {} bytes, {}); original references {:?}.",
            read.object.scope,
            read.object.path,
            read.object.version,
            read.object.byte_length,
            read.object.content_sha256,
            read.requested_as,
        ));
    }
    for directory in &scope.directories {
        lines.push(format!(
            "Directory {:?}: {}; direct entries including hidden entries only, without recursion, symlink traversal or file-content reads.",
            directory.path,
            directory
                .permissions
                .iter()
                .map(|p| p.action())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !scope.directories.is_empty() {
        lines.push("Directory paths come from caller context, not directory snapshots or OS identities. Backends must verify directories and direct parent-child relationships in the same namespace, and reject unsupported exact permissions.".into());
    }
    if scope.reads.is_empty() {
        lines.push("No file-read permissions requested.".into());
    }
    lines.push(format!(
        "Forbid file changes, execution, network access and tool invocation: {}.",
        scope.forbidden_actions.join(", ")
    ));
    if scope.directories.is_empty() {
        lines.push(
            "Unlisted objects are denied by default; only the received snapshot is included, \
             without expanding to the whole repository or future files."
                .into(),
        );
    }
    lines.push(
        "Downstream services must verify that OS objects match this snapshot and complete \
         trusted approval, publication and enforcement."
            .into(),
    );
    for assumption in draft.assumptions() {
        lines.push(format!(
            "Reasoning assumption (not authorization): {assumption:?}"
        ));
    }
    for quality in draft.observed_only() {
        lines.push(format!(
            "Result quality requirement (not enforced by Cedar): {quality:?}"
        ));
    }
    lines
}

/// Render one read permit pinned to the task, revisions and candidate expiry.
fn read_permit(
    rule_id: &str,
    task: &EntityUid,
    file: &EntityUid,
    scope: &PermissionScope,
) -> String {
    format!(
        "{}permit (\n  \
           principal is AgentSec::Agent,\n  \
           action == AgentSec::Action::\"filesystem.read\",\n  \
           resource == {file}\n\
         ) when {{\n  \
           principal has task &&\n  \
           context has authorization &&\n  \
           principal.task == context.authorization.task &&\n  \
           context.authorization.task == {task} &&\n  \
           context.authorization.contract_revision == {} &&\n  \
           context.authorization.binding_revision == {} &&\n  \
           context.authorization.now < {}\n\
         }};\n",
        annotations(rule_id, None),
        scope.contract_revision,
        scope.binding_revision,
        scope.context.expires_at
    )
}

fn directory_permit(
    rule_id: &str,
    task: &EntityUid,
    directory: &EntityUid,
    permission: FilesystemPermission,
    scope: &PermissionScope,
) -> String {
    let target = if permission == FilesystemPermission::Metadata {
        format!(
            "(resource == {directory} || (resource has parent_directory && resource.parent_directory == {directory}))"
        )
    } else {
        format!("resource == {directory}")
    };
    format!(
        "{}permit (principal is AgentSec::Agent, action == AgentSec::Action::\"{}\", resource is AgentSec::FilesystemResource) when {{\n  \
         {target} && principal has task && context has authorization &&\n  \
         principal.task == context.authorization.task && context.authorization.task == {task} &&\n  \
         context.authorization.contract_revision == {} && context.authorization.binding_revision == {} &&\n  \
         context.authorization.now < {}\n}};\n",
        annotations(rule_id, None),
        permission.action(),
        scope.contract_revision,
        scope.binding_revision,
        scope.context.expires_at,
    )
}

/// Bind forbids to the trusted principal task, independent of request context and expiry.
fn side_effect_forbid(rule_id: &str, task: &EntityUid, forbidden_actions: &[&str]) -> String {
    let actions = forbidden_actions
        .iter()
        .map(|action| format!("    AgentSec::Action::\"{action}\""))
        .collect::<Vec<_>>()
        .join(",\n");
    format!(
        "{}forbid (\n  principal is AgentSec::Agent,\n  action in [\n{actions}\n  ],\n  resource\n) \
         when {{\n  principal has task && principal.task == {task}\n}};\n",
        annotations(rule_id, Some(DENY_MESSAGE))
    )
}

/// Render the annotation block every candidate rule carries.
fn annotations(rule_id: &str, deny_message: Option<&str>) -> String {
    let deny = deny_message
        .map(|message| format!("@asc_deny_message(\"{message}\")\n"))
        .unwrap_or_default();
    format!(
        "@id(\"{rule_id}\")\n\
         @asc_class(\"task_authorization\")\n\
         @asc_required_pep(\"gateway,sandbox\")\n\
         @asc_obligation(\"audit\")\n{deny}"
    )
}

/// Parse and validate the generated text, then confirm the parsed rule shape.
///
/// Re-reading our own output catches template drift before a candidate is handed
/// over, since the policy service only ever sees the serialized text.
fn verify(
    policy_set: &str,
    rule_sources: &BTreeMap<String, Vec<String>>,
) -> Result<(), PolicyError> {
    let policies = PolicySet::from_str(policy_set).map_err(|_| PolicyError::Syntax)?;
    let (schema, _) =
        Schema::from_cedarschema_str(CEDAR_SCHEMA).map_err(|_| PolicyError::Schema)?;
    if !Validator::new(schema)
        .validate(&policies, ValidationMode::Strict)
        .validation_passed()
    {
        return Err(PolicyError::Schema);
    }
    if policies.policies().count() != rule_sources.len() {
        return Err(PolicyError::RuleShape);
    }
    let mut declared_ids = BTreeSet::new();
    for policy in policies.policies() {
        let declared_id = policy.annotation("id").unwrap_or_default();
        let is_forbid = declared_id.ends_with("-deny-side-effects");
        if policy.annotation("asc_class") != Some("task_authorization")
            || policy.annotation("asc_required_pep") != Some("gateway,sandbox")
            || policy.annotation("asc_obligation") != Some("audit")
            || !declared_ids.insert(declared_id)
            || !rule_sources.contains_key(declared_id)
            || (policy.effect() == Effect::Forbid) != is_forbid
            || (is_forbid && policy.annotation("asc_deny_message") != Some(DENY_MESSAGE))
        {
            return Err(PolicyError::RuleShape);
        }
    }
    Ok(())
}

/// Build an entity reference through Cedar instead of splicing raw identifiers.
fn entity_uid(entity_type: &str, id: &str) -> Result<EntityUid, PolicyError> {
    let entity_type = EntityTypeName::from_str(entity_type).map_err(|_| PolicyError::Syntax)?;
    Ok(EntityUid::from_type_name_and_id(
        entity_type,
        EntityId::new(id),
    ))
}
