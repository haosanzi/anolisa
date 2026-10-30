//! Compile the audited read-only template and evaluate the result with the
//! official Cedar authorizer: bound reads allow, everything else denies.

use asc_intent::{
    CEDAR_SCHEMA, CandidatePolicy, INTENT_BUDGET, MAX_MATERIAL_BYTES, Material, MaterialVersion,
    ProposalContext, ProposalError, ProposalOutcome, RejectionReason, ResourceScope,
    ResourceSnapshot, ScopeKind, SnapshotError, SnapshotSource, TaskInput, propose_task,
};
use asc_model_client::provider::{FakeProvider, ModelProvider, ProviderError};
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, PolicySet,
    Request, Schema, ValidationMode, Validator,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::str::FromStr as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const TASK: &str = "task-review-001";
const EXPIRES_AT: i64 = 2_000_001_800;

const ENTITIES: &str = r#"[
  {"uid": {"type": "AgentSec::Task", "id": "task-review-001"}, "attrs": {}, "parents": []},
  {
    "uid": {"type": "AgentSec::Agent", "id": "runtime-1"},
    "attrs": {"agent_type": "test", "task": {"__entity": {"type": "AgentSec::Task", "id": "task-review-001"}}},
    "parents": []
  },
  {
    "uid": {"type": "AgentSec::FilesystemResource", "id": "repo-A-main"},
    "attrs": {"path": "main.rs"}, "parents": []
  },
  {
    "uid": {"type": "AgentSec::FilesystemResource", "id": "repo-B-main"},
    "attrs": {"path": "main.rs"}, "parents": []
  },
  {"uid": {"type": "AgentSec::NetworkResource", "id": "all"}, "attrs": {}, "parents": []},
  {
    "uid": {"type": "AgentSec::ProcessResource", "id": "shell"},
    "attrs": {"program_path": "/bin/sh"}, "parents": []
  },
  {"uid": {"type": "AgentSec::ToolResource", "id": "shell"}, "attrs": {}, "parents": []}
]"#;

fn context() -> ProposalContext {
    ProposalContext::new(TASK.into(), EXPIRES_AT - 1800, 1800).unwrap()
}

fn scope(name: &str, kind: ScopeKind) -> ResourceScope {
    ResourceScope {
        name: name.into(),
        kind,
        base: (kind == ScopeKind::Changes).then(|| "head-1".into()),
    }
}

fn material(scope: &str, path: &str, version: MaterialVersion) -> Material {
    Material {
        scope: scope.into(),
        path: path.into(),
        version,
        content: b"SECRET_MATERIAL".to_vec(),
    }
}

fn snapshot(paths: &[&str]) -> ResourceSnapshot {
    ResourceSnapshot::new(
        &context(),
        SnapshotSource::Fixture,
        vec![scope("repo-A", ScopeKind::Changes)],
        paths
            .iter()
            .map(|path| material("repo-A", path, MaterialVersion::Current))
            .collect(),
    )
    .unwrap()
}

fn input(selectors: &[(&str, &str, Option<&str>)]) -> (TaskInput, Value) {
    let text = format!(
        "Review {}",
        selectors
            .iter()
            .map(|(raw, _, _)| *raw)
            .collect::<Vec<_>>()
            .join(" and ")
    );
    let task = TaskInput {
        source_id: "task-1".into(),
        text: text.clone(),
    };
    let reads: Vec<_> = selectors.iter().map(|(raw, _, _)| *raw).collect();
    let selectors: Vec<_> = selectors
        .iter()
        .map(|(_, kind, name)| {
            let mut selector = json!({"kind": kind});
            if let Some(name) = name {
                selector["name"] = json!(name);
            }
            selector
        })
        .collect();
    let draft = json!({
        "goal": text, "resources": {"read": reads, "write": [], "egress": []},
        "read_selectors": selectors,
        "requested_actions": if reads.is_empty() { json!([]) } else { json!(["read"]) },
        "prohibitions": [], "assumptions": [], "observed_only": [],
        "unresolved": [], "external_influences": []
    });
    (task, draft)
}

fn response(task: &TaskInput, draft: &Value) -> String {
    fn visit(value: &Value, path: &str, task: &TaskInput, evidence: &mut Vec<Value>) {
        match value {
            Value::String(_) => evidence
                .push(json!({"field": path, "source_id": task.source_id, "quote": task.text})),
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    visit(value, &format!("{path}/{index}"), task, evidence);
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    visit(value, &format!("{path}/{key}"), task, evidence);
                }
            }
            _ => panic!("unexpected fixture leaf"),
        }
    }
    let mut evidence = Vec::new();
    visit(draft, "", task, &mut evidence);
    let mut draft = draft.clone();
    draft["evidence"] = json!(evidence);
    draft.to_string()
}

fn propose(
    input: &(TaskInput, Value),
    snapshot: &ResourceSnapshot,
    context: &ProposalContext,
) -> ProposalOutcome {
    propose_task(
        &FakeProvider::new(response(&input.0, &input.1)),
        "fixture",
        &input.0,
        snapshot,
        context,
        Instant::now() + INTENT_BUDGET,
    )
    .unwrap()
}

fn candidate(
    input: &(TaskInput, Value),
    snapshot: &ResourceSnapshot,
    context: &ProposalContext,
) -> Box<CandidatePolicy> {
    match propose(input, snapshot, context) {
        ProposalOutcome::Candidate { candidate } => candidate,
        other => panic!("{}", serde_json::to_string(&other).unwrap()),
    }
}

fn changes() -> (TaskInput, Value) {
    input(&[("repo-A changes", "changes", Some("repo-A"))])
}

fn uid(entity_type: &str, id: &str) -> EntityUid {
    EntityUid::from_type_name_and_id(
        EntityTypeName::from_str(entity_type).unwrap(),
        EntityId::new(id),
    )
}

/// Evaluate one synthetic request against the candidate with trusted context.
fn decide(
    policy_set: &str,
    action: &str,
    resource: EntityUid,
    now: i64,
    revisions: (i64, i64),
) -> Decision {
    let mut context = json!({"authorization": {
        "task": {"__entity": {"type": "AgentSec::Task", "id": TASK}},
        "now": now,
        "contract_revision": revisions.0,
        "binding_revision": revisions.1
    }});
    if action == "process.spawn" {
        context["input"] = json!({"cwd": "/workspace", "arg_count": 0});
    }
    evaluate(
        policy_set,
        action,
        resource,
        json!({"agent_type": "test", "task": {
            "__entity": {"type": "AgentSec::Task", "id": TASK}
        }}),
        context,
    )
}

fn evaluate(
    policy_set: &str,
    action: &str,
    resource: EntityUid,
    principal_attrs: Value,
    context: Value,
) -> Decision {
    let (schema, _) = Schema::from_cedarschema_str(CEDAR_SCHEMA).unwrap();
    let action = uid("AgentSec::Action", action);
    let context = Context::from_json_value(context, Some((&schema, &action))).unwrap();
    let mut entities: Value = serde_json::from_str(ENTITIES).unwrap();
    entities[1]["attrs"] = principal_attrs;
    if resource.type_name().to_string() == "AgentSec::FilesystemResource" {
        let id = resource.id().unescaped();
        if !entities
            .as_array()
            .unwrap()
            .iter()
            .any(|entity| entity["uid"]["id"] == id)
        {
            entities.as_array_mut().unwrap().push(json!({
                "uid": {"type": "AgentSec::FilesystemResource", "id": id},
                "attrs": {"path": "main.rs"}, "parents": []
            }));
        }
    }
    let request = Request::new(
        uid("AgentSec::Agent", "runtime-1"),
        action,
        resource,
        context,
        Some(&schema),
    )
    .unwrap();
    let response = Authorizer::new().is_authorized(
        &request,
        &PolicySet::from_str(policy_set).unwrap(),
        &Entities::from_json_value(entities, Some(&schema)).unwrap(),
    );
    assert_eq!(response.diagnostics().errors().count(), 0);
    response.decision()
}

fn count_input() -> (TaskInput, Value) {
    let mut result = input(&[("当前目录", "current_directory", Some("当前目录"))]);
    result.0.text = "当前目录下有几个文件".into();
    result.1["goal"] = json!("统计当前目录直接包含的文件数量");
    result.1["requested_actions"] = json!(["directory_listing", "metadata"]);
    result
}

#[test]
fn directory_bindings_are_contextual_deterministic_and_need_no_snapshot_contents() {
    let empty = ResourceSnapshot::new(&context(), SnapshotSource::Fixture, vec![], vec![]).unwrap();
    let task = count_input();
    let missing = serde_json::to_value(propose(&task, &empty, &context())).unwrap();
    assert_eq!(missing["outcome"], "needs_clarification");
    assert_eq!(
        missing["resource_issues"][0]["reason"],
        "missing_working_directory"
    );
    let snapshot = empty
        .clone()
        .with_working_directory("/caller/项目".into())
        .unwrap();
    let first = candidate(&task, &snapshot, &context());
    let second = candidate(&task, &snapshot, &context());
    assert_eq!(first.candidate_hash(), second.candidate_hash());
    let value = serde_json::to_value(&first).unwrap();
    assert_eq!(value["directories"][0]["path"], "/caller/项目");
    assert_eq!(value["reads"], json!([]));
    assert_eq!(value["binding_snapshot"]["objects"], json!([]));
    assert_eq!(
        value["required_permissions"],
        json!(["filesystem.list", "filesystem.metadata"])
    );
    let changed = empty
        .clone()
        .with_working_directory("/other".into())
        .unwrap();
    assert_ne!(
        first.candidate_hash(),
        candidate(&task, &changed, &context()).candidate_hash()
    );
    assert_ne!(snapshot.digest(), changed.digest());
    for cwd in [
        "relative", "/a/../b", "/a/./b", "/a//b", "/a/", "/a\\b", "/a\n",
    ] {
        assert!(
            empty.clone().with_working_directory(cwd.into()).is_err(),
            "{cwd:?}"
        );
    }
    assert!(empty.clone().with_working_directory("/".into()).is_ok());
    for (name, path) in [
        ("docs", "/caller/项目/docs"),
        ("./docs", "/caller/项目/docs"),
        (".", "/caller/项目"),
        ("/elsewhere", "/elsewhere"),
    ] {
        let mut task = input(&[(name, "directory", Some(name))]);
        task.1["requested_actions"] = json!(["directory_listing"]);
        let value = serde_json::to_value(candidate(&task, &snapshot, &context())).unwrap();
        assert_eq!(value["directories"][0]["path"], path);
        assert_eq!(value["required_permissions"], json!(["filesystem.list"]));
    }
    for name in ["../outside", "a/../b", "/a//b"] {
        let mut task = input(&[(name, "directory", Some(name))]);
        task.1["requested_actions"] = json!(["directory_listing"]);
        let value = serde_json::to_value(propose(&task, &snapshot, &context())).unwrap();
        assert_eq!(value["outcome"], "needs_clarification");
    }
    let mut mixed = count_input();
    mixed.1["requested_actions"] = json!(["read", "directory_listing"]);
    assert!(matches!(
        propose(&mixed, &snapshot, &context()),
        ProposalOutcome::Rejected { .. }
    ));
}

#[test]
fn directory_cedar_allows_only_listing_and_direct_entry_metadata_never_content() {
    let snapshot = ResourceSnapshot::new(&context(), SnapshotSource::Fixture, vec![], vec![])
        .unwrap()
        .with_working_directory("/caller".into())
        .unwrap();
    let candidate = candidate(&count_input(), &snapshot, &context());
    let value = serde_json::to_value(&candidate).unwrap();
    let directory = value["directories"][0]["entity_id"].as_str().unwrap();
    let (schema, _) = Schema::from_cedarschema_str(CEDAR_SCHEMA).unwrap();
    let mut entities: Value = serde_json::from_str(ENTITIES).unwrap();
    for (id, parent) in [
        (directory, None),
        ("child", Some(directory)),
        ("nested", Some("child")),
        ("sibling", None),
    ] {
        let mut attrs = json!({"path":id});
        if let Some(parent) = parent {
            attrs["parent_directory"] =
                json!({"__entity":{"type":"AgentSec::FilesystemResource","id":parent}});
        }
        entities.as_array_mut().unwrap().push(json!({"uid":{"type":"AgentSec::FilesystemResource","id":id},"attrs":attrs,"parents":[]}));
    }
    let entities = Entities::from_json_value(entities, Some(&schema)).unwrap();
    for (action, id, expected) in [
        ("filesystem.list", directory, Decision::Allow),
        ("filesystem.metadata", directory, Decision::Allow),
        ("filesystem.metadata", "child", Decision::Allow),
        ("filesystem.list", "child", Decision::Deny),
        ("filesystem.metadata", "nested", Decision::Deny),
        ("filesystem.metadata", "sibling", Decision::Deny),
        ("filesystem.read", directory, Decision::Deny),
        ("filesystem.read", "child", Decision::Deny),
        ("filesystem.write", "child", Decision::Deny),
    ] {
        let action = uid("AgentSec::Action", action);
        let context = Context::from_json_value(json!({"authorization":{
            "task":{"__entity":{"type":"AgentSec::Task","id":TASK}}, "now":EXPIRES_AT-1, "contract_revision":1,"binding_revision":1
        }}), Some((&schema, &action))).unwrap();
        let request = Request::new(
            uid("AgentSec::Agent", "runtime-1"),
            action,
            uid("AgentSec::FilesystemResource", id),
            context,
            Some(&schema),
        )
        .unwrap();
        let result = Authorizer::new().is_authorized(
            &request,
            &PolicySet::from_str(candidate.policy_set()).unwrap(),
            &entities,
        );
        assert_eq!(result.decision(), expected, "{id}");
        assert_eq!(result.diagnostics().errors().count(), 0);
    }
    let broad = format!(
        "{}\npermit(principal, action, resource);",
        candidate.policy_set()
    );
    assert_eq!(
        decide(
            &broad,
            "filesystem.read",
            uid("AgentSec::FilesystemResource", "child"),
            EXPIRES_AT - 1,
            (1, 1)
        ),
        Decision::Deny
    );
    for (now, revisions) in [
        (EXPIRES_AT, (1, 1)),
        (EXPIRES_AT - 1, (2, 1)),
        (EXPIRES_AT - 1, (1, 2)),
    ] {
        assert_eq!(
            decide(
                candidate.policy_set(),
                "filesystem.list",
                uid("AgentSec::FilesystemResource", directory),
                now,
                revisions
            ),
            Decision::Deny
        );
    }
}

#[test]
fn exact_snapshot_reads_allow_and_unselected_resources_deny() {
    let snapshot = snapshot(&["src/main.rs", "docs/guide.txt"]);
    let candidate = candidate(&changes(), &snapshot, &context());
    for object in snapshot.objects() {
        assert_eq!(
            decide(
                candidate.policy_set(),
                "filesystem.read",
                uid("AgentSec::FilesystemResource", &object.entity_id),
                EXPIRES_AT - 1,
                (1, 1)
            ),
            Decision::Allow
        );
    }
    assert_eq!(
        decide(
            candidate.policy_set(),
            "filesystem.read",
            uid("AgentSec::FilesystemResource", "repo-B-main"),
            EXPIRES_AT - 1,
            (1, 1)
        ),
        Decision::Deny
    );
    let selected = candidate.policy_set();
    for (now, revisions) in [
        (EXPIRES_AT, (1, 1)),
        (EXPIRES_AT - 1, (2, 1)),
        (EXPIRES_AT - 1, (1, 2)),
    ] {
        assert_eq!(
            decide(
                selected,
                "filesystem.read",
                uid(
                    "AgentSec::FilesystemResource",
                    &snapshot.objects()[0].entity_id
                ),
                now,
                revisions
            ),
            Decision::Deny
        );
    }
    let other_task = selected.replace(TASK, "other-task");
    assert_eq!(
        decide(
            &other_task,
            "filesystem.read",
            uid(
                "AgentSec::FilesystemResource",
                &snapshot.objects()[0].entity_id
            ),
            EXPIRES_AT - 1,
            (1, 1)
        ),
        Decision::Deny
    );
}

#[test]
fn side_effect_forbids_override_even_a_test_only_broad_permit() {
    let candidate = candidate(&changes(), &snapshot(&["main.rs"]), &context());
    for policy in [
        candidate.policy_set().to_owned(),
        format!(
            "{}\npermit(principal, action, resource);",
            candidate.policy_set()
        ),
    ] {
        for action in [
            "filesystem.write",
            "filesystem.create",
            "filesystem.delete",
            "filesystem.rename",
            "filesystem.chmod",
            "filesystem.execute",
            "process.spawn",
            "network.use",
            "tool.invoke",
        ] {
            let resource = match action {
                "network.use" => uid("AgentSec::NetworkResource", "all"),
                "process.spawn" => uid("AgentSec::ProcessResource", "shell"),
                "tool.invoke" => uid("AgentSec::ToolResource", "shell"),
                _ => uid("AgentSec::FilesystemResource", "repo-A-main"),
            };
            assert_eq!(
                decide(&policy, action, resource, EXPIRES_AT + 1, (1, 1)),
                Decision::Deny
            );
        }
    }
}

#[test]
fn candidate_has_same_source_rules_summary_and_pending_status() {
    let snapshot = snapshot(&["main.rs"]);
    let candidate = candidate(&changes(), &snapshot, &context());
    let output = serde_json::to_value(&candidate).unwrap();
    assert_eq!(output["format_version"], "asc.intent.candidate.v1");
    assert_eq!(output["kind"], "initial");
    assert_eq!(output["status"], "CANDIDATE");
    assert_eq!(output["authorization_required"], true);
    assert_eq!(
        output["schema_sha256"],
        format!("sha256:{:x}", Sha256::digest(CEDAR_SCHEMA.as_bytes()))
    );
    assert!(!candidate.policy_set().contains("ASC::"));
    assert_eq!(output["binding_snapshot_digest"], snapshot.digest());
    assert_eq!(output["rule_sources"].as_object().unwrap().len(), 2);
    let id = &snapshot.objects()[0].entity_id;
    assert_eq!(
        output["rule_sources"][format!("{TASK}-read-{id}")],
        json!(["repo-A changes"])
    );
    let summary = output["back_translation"].to_string();
    assert!(summary.is_ascii());
    assert!(summary.contains("Pending approval; not effective."));
    assert!(summary.contains("repo-A changes"));
    assert!(summary.contains("main.rs"));
    assert!(summary.contains(&snapshot.objects()[0].content_sha256));
    for action in output["forbidden_actions"].as_array().unwrap() {
        let action = action.as_str().unwrap();
        assert!(summary.contains(action));
        assert!(candidate.policy_set().contains(action));
    }
    assert!(candidate.policy_set().contains("@asc_deny_message("));
    assert!(!output.to_string().contains("SECRET_MATERIAL"));
}

#[test]
fn resource_selection_never_widens_or_picks_the_first_ambiguous_file() {
    let snapshot = snapshot(&["report.csv", "nested/report.csv", "src/a.rs"]);
    for (raw, kind, name, reason) in [
        (
            "report.csv",
            "file",
            Some("report.csv"),
            "ambiguous_resource",
        ),
        (
            "missing.txt",
            "file",
            Some("missing.txt"),
            "missing_resource",
        ),
        ("src", "directory", Some("src"), "incomplete_directory"),
        (
            "src/a.rs",
            "attachment",
            Some("src/a.rs"),
            "missing_resource",
        ),
        (
            "../report.csv",
            "file",
            Some("../report.csv"),
            "missing_resource",
        ),
        (
            "repo-B changes",
            "changes",
            Some("repo-B"),
            "missing_resource",
        ),
    ] {
        let outcome = propose(&input(&[(raw, kind, name)]), &snapshot, &context());
        assert_eq!(outcome.exit_code(), 2);
        let output = serde_json::to_value(outcome).unwrap();
        assert!(output.get("candidate").is_none());
        assert_eq!(output["resource_issues"][0]["reason"], reason);
        if reason == "ambiguous_resource" {
            assert_eq!(
                output["resource_issues"][0]["alternatives"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
        }
    }
    let candidate = candidate(
        &input(&[("repo-A/report.csv", "file", Some("repo-A/report.csv"))]),
        &snapshot,
        &context(),
    );
    let output = serde_json::to_value(candidate).unwrap();
    assert_eq!(output["reads"].as_array().unwrap().len(), 1);
    assert_eq!(output["reads"][0]["object"]["path"], "report.csv");
}

#[test]
fn changes_include_deleted_and_renamed_sides_but_file_reads_require_current() {
    let context = context();
    let snapshot = ResourceSnapshot::new(
        &context,
        SnapshotSource::RequestSnapshot,
        vec![scope("repo-A", ScopeKind::Changes)],
        vec![
            material("repo-A", "old.rs", MaterialVersion::Before),
            material("repo-A", "new.rs", MaterialVersion::Current),
        ],
    )
    .unwrap();
    let candidate = candidate(
        &input(&[("current changes", "changes", None)]),
        &snapshot,
        &context,
    );
    assert_eq!(
        serde_json::to_value(candidate).unwrap()["reads"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        propose(
            &input(&[("old.rs", "file", Some("old.rs"))]),
            &snapshot,
            &context
        )
        .exit_code(),
        2
    );
    let ambiguous = ResourceSnapshot::new(
        &context,
        SnapshotSource::Fixture,
        vec![
            scope("repo-A", ScopeKind::Changes),
            scope("repo-B", ScopeKind::Changes),
        ],
        vec![],
    )
    .unwrap();
    let output = serde_json::to_value(propose(
        &input(&[("current changes", "changes", None)]),
        &ambiguous,
        &context,
    ))
    .unwrap();
    assert_eq!(output["resource_issues"][0]["reason"], "ambiguous_resource");
}

#[test]
fn explicit_directories_and_attachments_only_resolve_their_frozen_members() {
    let context = context();
    let snapshot = ResourceSnapshot::new(
        &context,
        SnapshotSource::RequestSnapshot,
        vec![
            scope("docs", ScopeKind::Directory),
            scope("uploads", ScopeKind::Attachment),
        ],
        vec![
            material("docs", "docs/a.txt", MaterialVersion::Current),
            material("uploads", "docs-other/b.txt", MaterialVersion::Current),
        ],
    )
    .unwrap();
    for (raw, kind, name, path) in [
        ("docs", "directory", "docs", "docs/a.txt"),
        ("b.txt", "attachment", "b.txt", "docs-other/b.txt"),
    ] {
        let candidate = candidate(&input(&[(raw, kind, Some(name))]), &snapshot, &context);
        let output = serde_json::to_value(candidate).unwrap();
        assert_eq!(output["reads"].as_array().unwrap().len(), 1);
        assert_eq!(output["reads"][0]["object"]["path"], path);
    }
}

#[test]
fn directory_basename_aliases_preserve_exact_membership_and_ambiguity() {
    let context = context();
    let build = |names: &[&str]| {
        ResourceSnapshot::new(
            &context,
            SnapshotSource::RequestSnapshot,
            names
                .iter()
                .map(|name| scope(name, ScopeKind::Directory))
                .collect(),
            names
                .iter()
                .flat_map(|name| {
                    [
                        material(name, &format!("{name}/sub/a.txt"), MaterialVersion::Current),
                        material(
                            name,
                            &format!("{name}/sibling/b.txt"),
                            MaterialVersion::Current,
                        ),
                    ]
                })
                .collect(),
        )
        .unwrap()
    };
    let snapshot = build(&["root/project/docs"]);
    for name in ["docs/sub", "root/project/docs/sub"] {
        let output = serde_json::to_value(candidate(
            &input(&[(name, "directory", Some(name))]),
            &snapshot,
            &context,
        ))
        .unwrap();
        assert_eq!(output["reads"].as_array().unwrap().len(), 1);
        assert_eq!(
            output["reads"][0]["object"]["path"],
            "root/project/docs/sub/a.txt"
        );
    }
    let snapshot = build(&["root/a/docs", "root/b/docs"]);
    let output = serde_json::to_value(propose(
        &input(&[("docs", "directory", Some("docs"))]),
        &snapshot,
        &context,
    ))
    .unwrap();
    assert_eq!(output["outcome"], "needs_clarification");
    assert_eq!(output["resource_issues"][0]["reason"], "ambiguous_resource");
    assert!(output.get("candidate").is_none());
    assert_eq!(
        propose(
            &input(&[("docs", "file", Some("docs"))]),
            &snapshot,
            &context
        )
        .exit_code(),
        2
    );
}

#[test]
fn snapshots_reject_unsafe_paths_duplicate_objects_and_unbounded_materials() {
    let context = context();
    for path in [
        "",
        "/root/key",
        "../key",
        "docs/../key",
        "docs//key",
        "docs/./key",
        "docs\\key",
        "docs/\nkey",
    ] {
        assert!(matches!(
            ResourceSnapshot::new(
                &context,
                SnapshotSource::Fixture,
                vec![scope("repo-A", ScopeKind::Changes)],
                vec![material("repo-A", path, MaterialVersion::Current)]
            ),
            Err(SnapshotError::InvalidMaterial)
        ));
    }
    for materials in [
        vec![
            material("repo-A", "a", MaterialVersion::Current),
            material("repo-A", "a", MaterialVersion::Current),
        ],
        vec![material("repo-A", "a", MaterialVersion::Before)],
    ] {
        assert!(
            ResourceSnapshot::new(
                &context,
                SnapshotSource::Fixture,
                vec![scope("repo-A", ScopeKind::Attachment)],
                materials
            )
            .is_err()
        );
    }
    assert!(
        ResourceSnapshot::new(
            &context,
            SnapshotSource::Fixture,
            vec![scope("docs", ScopeKind::Directory)],
            vec![material("docs", "docs-sibling/a", MaterialVersion::Current)]
        )
        .is_err()
    );
    assert!(
        ResourceSnapshot::new(
            &context,
            SnapshotSource::Fixture,
            vec![
                scope("repo-A", ScopeKind::Changes),
                scope("repo-A", ScopeKind::Changes)
            ],
            vec![]
        )
        .is_err()
    );
    let mut invalid_base = scope("repo-A", ScopeKind::Changes);
    invalid_base.base = None;
    assert!(
        ResourceSnapshot::new(
            &context,
            SnapshotSource::Fixture,
            vec![invalid_base],
            vec![]
        )
        .is_err()
    );
}

#[test]
fn snapshots_bound_bytes_metadata_counts_and_reject_forged_identity() {
    let context = context();
    let mut large = material("repo-A", "a", MaterialVersion::Current);
    large.content = vec![0; MAX_MATERIAL_BYTES + 1];
    for materials in [
        vec![large],
        (0..257)
            .map(|i| material("repo-A", &format!("{i}"), MaterialVersion::Current))
            .collect(),
        (0..70)
            .map(|i| {
                material(
                    "repo-A",
                    &format!("{i}{}", "x".repeat(4000)),
                    MaterialVersion::Current,
                )
            })
            .collect(),
    ] {
        assert!(matches!(
            ResourceSnapshot::new(
                &context,
                SnapshotSource::Fixture,
                vec![scope("repo-A", ScopeKind::Changes)],
                materials
            ),
            Err(SnapshotError::TooLarge)
        ));
    }
    for (kind, forged) in [
        ("entity_id", json!("trusted-file")),
        ("content_sha256", json!("sha256:fake")),
        ("approved", json!(true)),
    ] {
        let mut dto = json!({"scope": "repo-A", "path": "a", "version": "current", "content": []});
        dto[kind] = forged;
        assert!(serde_json::from_value::<Material>(dto).is_err());
    }
}

#[test]
fn adding_cwd_rechecks_the_complete_snapshot_metadata_budget() {
    let scopes = (0..32)
        .map(|i| {
            scope(
                &format!("{i:02}{}", "x".repeat(4010)),
                ScopeKind::Attachment,
            )
        })
        .collect();
    let snapshot =
        ResourceSnapshot::new(&context(), SnapshotSource::Fixture, scopes, vec![]).unwrap();
    let bytes = serde_json::to_vec(&snapshot).unwrap().len();
    assert!(bytes > 256 * 1024 - 4096 && bytes <= 256 * 1024, "{bytes}");
    assert!(matches!(
        snapshot.with_working_directory(format!("/{}", "x".repeat(4095))),
        Err(SnapshotError::TooLarge)
    ));
}

#[test]
fn snapshot_hash_binds_content_membership_source_scope_version_and_proposal() {
    let original = snapshot(&["a"]);
    for change in 0..7 {
        let context = if change == 0 {
            ProposalContext::new("another-task".into(), EXPIRES_AT - 1800, 1800).unwrap()
        } else {
            context()
        };
        let source = if change == 1 {
            SnapshotSource::RequestSnapshot
        } else {
            SnapshotSource::Fixture
        };
        let mut scopes = vec![scope("repo-A", ScopeKind::Changes)];
        let mut materials = vec![material("repo-A", "a", MaterialVersion::Current)];
        match change {
            2 => scopes[0].base = Some("head-2".into()),
            3 => materials[0].content.push(b'!'),
            4 => materials[0].path = "b".into(),
            5 => materials[0].version = MaterialVersion::Before,
            6 => materials.push(material("repo-A", "b", MaterialVersion::Current)),
            _ => {}
        }
        let changed = ResourceSnapshot::new(&context, source, scopes, materials).unwrap();
        assert_ne!(changed.digest(), original.digest());
        assert_ne!(
            candidate(&changes(), &changed, &context).candidate_hash(),
            candidate(&changes(), &original, &self::context()).candidate_hash()
        );
        if change == 0 {
            assert_ne!(
                changed.objects()[0].entity_id,
                original.objects()[0].entity_id
            );
        }
    }
}

struct InspectProvider {
    response: String,
    calls: AtomicUsize,
    delay: Duration,
    fail: bool,
}

impl ModelProvider for InspectProvider {
    fn complete(&self, _: &str, _: &str, input: &str, _: Instant) -> Result<String, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(!input.contains("SECRET_MATERIAL"));
        let input: Value = serde_json::from_str(input).unwrap();
        assert_eq!(input.as_object().unwrap().len(), 1);
        assert!(input["task"]["text"].is_string());
        std::thread::sleep(self.delay);
        if self.fail {
            Err(ProviderError::Transport)
        } else {
            Ok(self.response.clone())
        }
    }
}

#[test]
fn proposal_deadline_context_and_provider_failures_never_return_a_candidate() {
    let input = changes();
    let snapshot = snapshot(&["a"]);
    let mut provider = InspectProvider {
        response: response(&input.0, &input.1),
        calls: AtomicUsize::new(0),
        delay: Duration::ZERO,
        fail: false,
    };
    assert!(
        propose_task(
            &provider,
            "fixture",
            &input.0,
            &snapshot,
            &context(),
            Instant::now()
        )
        .is_err()
    );
    let other = ProposalContext::new("other".into(), EXPIRES_AT - 1800, 1800).unwrap();
    assert!(matches!(
        propose_task(
            &provider,
            "fixture",
            &input.0,
            &snapshot,
            &other,
            Instant::now() + INTENT_BUDGET
        ),
        Err(ProposalError::InvalidContext)
    ));
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    let outcome = propose_task(
        &provider,
        "fixture",
        &input.0,
        &snapshot,
        &context(),
        Instant::now() + INTENT_BUDGET,
    )
    .unwrap();
    assert_eq!(outcome.exit_code(), 0);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    provider.fail = true;
    assert!(
        propose_task(
            &provider,
            "fixture",
            &input.0,
            &snapshot,
            &context(),
            Instant::now() + INTENT_BUDGET
        )
        .is_err()
    );
    provider.fail = false;
    provider.delay = Duration::from_millis(20);
    assert!(
        propose_task(
            &provider,
            "fixture",
            &input.0,
            &snapshot,
            &context(),
            Instant::now() + Duration::from_millis(5)
        )
        .is_err()
    );
    let expired = ProposalContext::new(TASK.into(), EXPIRES_AT, 1).unwrap();
    std::thread::sleep(Duration::from_millis(1010));
    assert!(matches!(
        propose_task(
            &provider,
            "fixture",
            &input.0,
            &snapshot,
            &expired,
            Instant::now() + INTENT_BUDGET
        ),
        Err(ProposalError::DeadlineExceeded)
    ));
    for (id, created, ttl) in [
        ("", 1, 1),
        ("task\"", 1, 1),
        (TASK, 0, 1),
        (TASK, -1, 1),
        (TASK, i64::MAX, 1),
        (TASK, 1, 0),
        (TASK, 1, 1801),
    ] {
        assert!(ProposalContext::new(id.into(), created, ttl).is_err());
    }
    assert!(ProposalContext::new("x".repeat(129), 1, 1).is_err());
}

#[test]
fn candidate_size_is_bounded_and_non_authorizing_notes_are_explicit() {
    let paths: Vec<_> = (0..150)
        .map(|index| format!("{index}{}", "x".repeat(1000)))
        .collect();
    let snapshot = snapshot(&paths.iter().map(String::as_str).collect::<Vec<_>>());
    let input = changes();
    assert!(matches!(
        propose_task(
            &FakeProvider::new(response(&input.0, &input.1)),
            "fixture",
            &input.0,
            &snapshot,
            &context(),
            Instant::now() + INTENT_BUDGET
        ),
        Err(ProposalError::Policy(asc_intent::PolicyError::TooLarge))
    ));
    let mut input = changes();
    input.1["assumptions"] = json!(["assumption"]);
    input.1["observed_only"] = json!(["quality"]);
    let candidate = candidate(&input, &self::snapshot(&["a"]), &context());
    let output = serde_json::to_value(candidate).unwrap();
    let lines = output["back_translation"].as_array().unwrap();
    assert!(
        lines
            .iter()
            .any(|line| line.as_str().unwrap().contains("not authorization")
                && line.as_str().unwrap().contains("assumption"))
    );
    assert!(lines.iter().any(
        |line| line.as_str().unwrap().contains("not enforced by Cedar")
            && line.as_str().unwrap().contains("quality")
    ));
}

#[test]
fn file_directory_conflicts_cannot_be_silently_selected() {
    let snapshot = ResourceSnapshot::new(
        &context(),
        SnapshotSource::Fixture,
        vec![
            scope("docs", ScopeKind::Directory),
            scope("repo-A", ScopeKind::Changes),
        ],
        vec![
            material("docs", "docs/a", MaterialVersion::Current),
            material("repo-A", "docs", MaterialVersion::Current),
        ],
    )
    .unwrap();
    for kind in ["file", "directory"] {
        let output = serde_json::to_value(propose(
            &input(&[("docs", kind, Some("docs"))]),
            &snapshot,
            &context(),
        ))
        .unwrap();
        assert_eq!(output["resource_issues"][0]["reason"], "ambiguous_resource");
        assert_eq!(
            output["resource_issues"][0]["alternatives"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
    assert!(matches!(
        ResourceSnapshot::new(
            &context(),
            SnapshotSource::Fixture,
            vec![scope("repo-A", ScopeKind::Changes)],
            vec![
                material("repo-A", "a", MaterialVersion::Current),
                material("repo-A", "a/b", MaterialVersion::Current)
            ]
        ),
        Err(SnapshotError::InvalidMaterial)
    ));
}

fn content_hash(value: &Value) -> String {
    fn ordered(value: &Value) -> Value {
        match value {
            Value::Object(values) => {
                let sorted: std::collections::BTreeMap<_, _> =
                    values.iter().map(|(k, v)| (k, ordered(v))).collect();
                serde_json::to_value(sorted).unwrap()
            }
            Value::Array(values) => Value::Array(values.iter().map(ordered).collect()),
            value => value.clone(),
        }
    }
    format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&ordered(value)).unwrap())
    )
}

#[test]
fn hash_covers_every_field_and_is_order_independent() {
    let first = candidate(&changes(), &snapshot(&["b.rs", "a.rs"]), &context());
    let second = candidate(&changes(), &snapshot(&["a.rs", "b.rs"]), &context());
    assert_eq!(first.candidate_hash(), second.candidate_hash());
    let mut output = serde_json::to_value(&first).unwrap();
    output.as_object_mut().unwrap().remove("candidate_hash");
    assert_eq!(content_hash(&output), first.candidate_hash());
    for field in output.as_object().unwrap().keys() {
        let mut changed = output.clone();
        changed[field] = json!("modified");
        assert_ne!(content_hash(&changed), first.candidate_hash(), "{field}");
    }
    output.as_object_mut().unwrap().sort_keys();
    assert_eq!(content_hash(&output), first.candidate_hash());
    let other_time = ProposalContext::new(TASK.into(), EXPIRES_AT - 1800, 1799).unwrap();
    assert_ne!(
        candidate(&changes(), &snapshot(&["a.rs", "b.rs"]), &other_time).candidate_hash(),
        first.candidate_hash()
    );
    let mut other_input = changes();
    other_input.0.text += "; extra context";
    assert_ne!(
        candidate(&other_input, &snapshot(&["a.rs", "b.rs"]), &context()).candidate_hash(),
        first.candidate_hash()
    );
}

#[test]
fn original_names_cannot_inject_cedar_and_aliases_preserve_all_sources() {
    let raw = "repo-A changes\") || true; // injection";
    let candidate = candidate(
        &input(&[
            (raw, "changes", Some("repo-A")),
            ("main.rs", "file", Some("main.rs")),
        ]),
        &snapshot(&["main.rs"]),
        &context(),
    );
    assert!(!candidate.policy_set().contains("injection"));
    let output = serde_json::to_value(candidate).unwrap();
    assert_eq!(output["reads"].as_array().unwrap().len(), 1);
    assert_eq!(output["reads"][0]["requested_as"], json!(["main.rs", raw]));
    assert_eq!(output["rule_sources"].as_object().unwrap().len(), 2);
}

#[test]
fn unsupported_effects_and_destinations_never_become_partial_candidates() {
    for action in [
        "file_mutation",
        "process_execution",
        "network_access",
        "remote_publication",
    ] {
        let mut input = changes();
        input.0.text.push_str("; ");
        input.0.text.push_str(action);
        input.1["requested_actions"] = json!(["read", action]);
        let outcome = propose(&input, &snapshot(&["main.rs"]), &context());
        assert_eq!(outcome.exit_code(), 3);
        assert!(matches!(outcome, ProposalOutcome::Rejected { .. }));
        // Unsupported effects reject even when a scoped exclusion also lists the category
        // or the model adds unresolved notes; clarifying cannot make them supported.
        input.1["prohibitions"] = json!([action]);
        input.0.text += "; recursion unclear";
        input.1["unresolved"] = json!(["recursion unclear"]);
        assert!(matches!(
            propose(&input, &snapshot(&["main.rs"]), &context()),
            ProposalOutcome::Rejected {
                reason: RejectionReason::UnsupportedRequest,
                ..
            }
        ));
    }
    let mut input = changes();
    input.0.text += "; no read";
    input.1["prohibitions"] = json!(["read"]);
    assert!(matches!(
        propose(&input, &snapshot(&["main.rs"]), &context()),
        ProposalOutcome::NeedsClarification { .. }
    ));
    for destination in ["write", "egress"] {
        let mut input = changes();
        input.0.text += "; output.txt";
        input.1["resources"][destination] = json!(["output.txt"]);
        assert!(matches!(
            propose(&input, &snapshot(&["main.rs"]), &context()),
            ProposalOutcome::Rejected { .. }
        ));
    }
}

#[test]
fn absent_reads_require_clarification_but_pure_reasoning_has_no_permit() {
    let snapshot = snapshot(&[]);
    let mut request = input(&[]);
    let candidate = candidate(&request, &snapshot, &context());
    assert!(!candidate.policy_set().contains("permit ("));
    let output = serde_json::to_value(&candidate).unwrap();
    let summary = output["back_translation"].to_string();
    assert!(summary.is_ascii());
    assert!(summary.contains("No file-read permissions requested."));
    for action in ["filesystem.read", "filesystem.write"] {
        assert_eq!(
            decide(
                candidate.policy_set(),
                action,
                uid("AgentSec::FilesystemResource", "repo-A-main"),
                EXPIRES_AT - 1,
                (1, 1)
            ),
            Decision::Deny
        );
    }
    request.1["requested_actions"] = json!(["read"]);
    assert_eq!(propose(&request, &snapshot, &context()).exit_code(), 2);
    let mut request = changes();
    request.1["requested_actions"] = json!([]);
    assert_eq!(propose(&request, &snapshot, &context()).exit_code(), 2);
    request.1["unresolved"] = json!(["scope unclear"]);
    assert!(matches!(
        propose(&request, &snapshot, &context()),
        ProposalOutcome::NeedsClarification { .. }
    ));
}

#[test]
fn task_binding_and_authorization_context_are_both_required() {
    let snapshot = snapshot(&["main.rs"]);
    let candidate = candidate(&changes(), &snapshot, &context());
    let file = uid(
        "AgentSec::FilesystemResource",
        &snapshot.objects()[0].entity_id,
    );
    let attributes = json!({"agent_type": "test", "task": {
        "__entity": {"type": "AgentSec::Task", "id": TASK}
    }});
    let authorization = json!({"authorization": {
        "task": {"__entity": {"type": "AgentSec::Task", "id": TASK}},
        "now": EXPIRES_AT - 1, "contract_revision": 1, "binding_revision": 1
    }});
    for change in 0..4 {
        let mut attributes = attributes.clone();
        let mut context = authorization.clone();
        match change {
            0 => {
                attributes.as_object_mut().unwrap().remove("task");
            }
            1 => attributes["task"]["__entity"]["id"] = json!("other-task"),
            2 => context = json!({}),
            3 => context["authorization"]["task"]["__entity"]["id"] = json!("other-task"),
            _ => unreachable!(),
        }
        assert_eq!(
            evaluate(
                candidate.policy_set(),
                "filesystem.read",
                file.clone(),
                attributes,
                context
            ),
            Decision::Deny
        );
    }
    let policies = format!(
        "{}\npermit(principal, action, resource);",
        candidate.policy_set()
    );
    for context in [
        json!({}),
        json!({"authorization": {
            "task": {"__entity": {"type": "AgentSec::Task", "id": "other-task"}},
            "now": EXPIRES_AT + 1, "contract_revision": 9, "binding_revision": 9
        }}),
    ] {
        assert_eq!(
            evaluate(
                &policies,
                "filesystem.write",
                file.clone(),
                attributes.clone(),
                context
            ),
            Decision::Deny
        );
    }
}

#[test]
fn shared_schema_preserves_base_requests_and_checks_scan_facts() {
    let (schema, _) = Schema::from_cedarschema_str(CEDAR_SCHEMA).unwrap();
    let mut entities: Value = serde_json::from_str(ENTITIES).unwrap();
    entities[1]["attrs"] = json!({"agent_type": "test", "pid": 123});
    assert!(Entities::from_json_value(entities, Some(&schema)).is_ok());
    for (action, resource_type, resource_id, context) in [
        ("filesystem.read", "FilesystemResource", "main", json!({})),
        ("filesystem.write", "FilesystemResource", "main", json!({})),
        (
            "filesystem.execute",
            "FilesystemResource",
            "main",
            json!({}),
        ),
        ("network.use", "NetworkResource", "all", json!({})),
        (
            "process.spawn",
            "ProcessResource",
            "shell",
            json!({"input": {
                "cwd": "/workspace", "arg_count": 2, "arg1": "-c", "arg2": "true"
            }}),
        ),
        ("tool.invoke", "ToolResource", "shell", json!({})),
        (
            "content.accept",
            "ContentResource",
            "user_prompt",
            json!({}),
        ),
    ] {
        let action = uid("AgentSec::Action", action);
        let context = Context::from_json_value(context, Some((&schema, &action))).unwrap();
        assert!(
            Request::new(
                uid("AgentSec::Agent", "runtime-1"),
                action,
                uid(&format!("AgentSec::{resource_type}"), resource_id),
                context,
                Some(&schema)
            )
            .is_ok()
        );
    }
    let action = uid("AgentSec::Action", "tool.invoke");
    let facts = json!({
        "pii": {"verdict": {"__entity": {"type": "AgentSec::ScanVerdict", "id": "pass"}}},
        "code": {"verdict": {"__entity": {"type": "AgentSec::ScanVerdict", "id": "deny"}}},
        "skill": {"latest_status": {"__entity": {"type": "AgentSec::SkillStatus", "id": "drifted"}},
                  "reason_code": "changed", "active_version": "v1"},
        "sandbox": {"block_match": false, "filesystem_risk": true, "network_match": false}
    });
    let request_is_valid = |facts| {
        Context::from_json_value(facts, Some((&schema, &action))).is_ok_and(|context| {
            Request::new(
                uid("AgentSec::Agent", "runtime-1"),
                action.clone(),
                uid("AgentSec::ToolResource", "shell"),
                context,
                Some(&schema),
            )
            .is_ok()
        })
    };
    assert!(request_is_valid(facts.clone()));
    for change in 0..4 {
        let mut invalid = facts.clone();
        match change {
            0 => invalid["pii"]["verdict"] = json!("pass"),
            1 => invalid["pii"]["verdict"]["__entity"]["id"] = json!("unknown"),
            2 => invalid["skill"]["latest_status"]["__entity"]["id"] = json!("unknown"),
            3 => invalid["sandbox"]["block_match"] = json!("false"),
            _ => unreachable!(),
        }
        assert!(
            !request_is_valid(invalid),
            "accepted invalid facts case {change}"
        );
    }
    let action = uid("AgentSec::Action", "process.spawn");
    assert!(Context::from_json_value(json!({}), Some((&schema, &action))).is_err());
}

#[test]
fn shared_schema_has_no_warnings_and_validates_candidates() {
    let (schema, warnings) = Schema::from_cedarschema_str(CEDAR_SCHEMA).unwrap();
    assert_eq!(warnings.count(), 0);
    let validator = Validator::new(schema);
    for paths in [vec![], vec!["a.rs"], vec!["a.rs", "b.rs"]] {
        let input = if paths.is_empty() {
            input(&[])
        } else {
            changes()
        };
        let candidate = candidate(&input, &snapshot(&paths), &context());
        let policies = PolicySet::from_str(candidate.policy_set()).unwrap();
        let result = validator.validate(&policies, ValidationMode::Strict);
        assert!(
            result.validation_passed(),
            "{:?}",
            result.validation_errors().collect::<Vec<_>>()
        );
    }
}
