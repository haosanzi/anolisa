//! Task candidates retry once when a permit tests `context`, which the launch authorizer cannot
//! read, or when a forbid is one the runtime protector cannot lower; the retry never costs the
//! valid first draft. A point grant on a link is reported, never retried, and every candidate
//! names which consumers can carry each requirement `@id`.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use asc_intent::{
    COVERAGE_NOTE, LAUNCH_VIEW_NOTE, POINT_ALIAS_NOTE, ProposalContext, ProposalOutcome,
    RUNTIME_VIEW_NOTE, TASK_BASE, TaskInput, launch_view_gaps, point_aliases, propose_task,
    requirement_coverage, runtime_view_gaps,
};
use asc_model_client::provider::{ModelProvider, ProviderError};
use serde_json::{Value, json};

const CWD_SPAWN: &str = r#"// [S3] launch
@id("spawn")
permit(principal, action == SecCore::Action::"process.spawn", resource is SecCore::Process)
when { context.input.cwd == "/srv/demo" && resource.program == "/usr/bin/bash" };
// [H1] keep the rollback package
forbid(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/previous.zip"
    && context.input.operation == SecCore::WriteOperation::"delete" };"#;
const PLAIN_SPAWN: &str = r#"// [S3] launch
permit(principal, action == SecCore::Action::"process.spawn", resource is SecCore::Process)
when { resource.program == "/usr/bin/bash" };
// [H1] keep the rollback package
forbid(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/previous.zip"
    && context.input.operation == SecCore::WriteOperation::"delete" };"#;

/// The artifact the program publishes for a model draft.
fn based(policy: &str) -> String {
    format!("{TASK_BASE}{policy}")
}

fn body(policy: &str) -> String {
    json!({"policy": policy, "unresolved": []}).to_string()
}

struct Scripted {
    responses: Mutex<VecDeque<Result<String, ProviderError>>>,
    payloads: Mutex<Vec<String>>,
}

impl Scripted {
    fn new(responses: Vec<Result<String, ProviderError>>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            payloads: Mutex::new(Vec::new()),
        }
    }

    fn payloads(&self) -> Vec<String> {
        self.payloads.lock().unwrap().clone()
    }
}

impl ModelProvider for Scripted {
    fn complete(
        &self,
        _: &str,
        _: &str,
        payload: &str,
        _: Instant,
    ) -> Result<String, ProviderError> {
        self.payloads.lock().unwrap().push(payload.to_owned());
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(ProviderError::Transport))
    }
}

fn propose(provider: &Scripted) -> Value {
    let outcome = propose_task(
        provider,
        "fixture",
        &TaskInput {
            source_id: "source".into(),
            text: "Build locally".into(),
        },
        &ProposalContext::new("task-1".into(), 2_000_000_000, 1800).unwrap(),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    assert!(matches!(outcome, ProposalOutcome::Candidate { .. }));
    serde_json::to_value(outcome).unwrap()["candidate"].clone()
}

fn launch_notes(candidate: &Value) -> Vec<String> {
    notes(candidate, LAUNCH_VIEW_NOTE)
}

fn notes(candidate: &Value, prefix: &str) -> Vec<String> {
    candidate["notes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .filter(|note| note.starts_with(prefix))
        .map(str::to_owned)
        .collect()
}

#[test]
fn gaps_name_context_permits_only() {
    assert_eq!(
        launch_view_gaps(CWD_SPAWN).unwrap(),
        [r#"permit #1 @id("spawn") (process.spawn) tests context.input.cwd"#]
    );
    // A forbid on `context.input.operation` is the runtime protector's input, not a gap.
    assert!(launch_view_gaps(PLAIN_SPAWN).unwrap().is_empty());
    let operation_permit = r#"permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/out" && context.input.operation == SecCore::WriteOperation::"create" };"#;
    assert_eq!(
        launch_view_gaps(operation_permit).unwrap(),
        ["permit #1 (file.write) tests context.input.operation"]
    );
}

#[test]
fn a_repaired_retry_replaces_the_first_draft() {
    let provider = Scripted::new(vec![Ok(body(CWD_SPAWN)), Ok(body(PLAIN_SPAWN))]);
    let candidate = propose(&provider);
    assert_eq!(candidate["artifact"]["text"], based(PLAIN_SPAWN));
    assert_eq!(candidate["draft"]["policy"], PLAIN_SPAWN);
    assert!(launch_notes(&candidate).is_empty());
    let payloads = provider.payloads();
    assert_eq!(payloads.len(), 2);
    assert!(!payloads[0].contains("上次输出被本地校验拒绝"));
    assert!(payloads[1].contains("context.input.cwd"));
}

#[test]
fn a_failed_retry_keeps_the_first_draft_and_reports_the_gap() {
    for retry in [
        Err(ProviderError::Transport),
        Ok("not json".to_owned()),
        Ok(body("permit(principal action, resource);")),
        Ok(body(CWD_SPAWN)),
    ] {
        let provider = Scripted::new(vec![Ok(body(CWD_SPAWN)), retry]);
        let candidate = propose(&provider);
        assert_eq!(candidate["artifact"]["text"], based(CWD_SPAWN));
        let notes = launch_notes(&candidate);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("context.input.cwd"), "{notes:?}");
    }
}

#[test]
fn a_clean_draft_is_not_retried() {
    let provider = Scripted::new(vec![Ok(body(PLAIN_SPAWN))]);
    let candidate = propose(&provider);
    assert_eq!(candidate["artifact"]["text"], based(PLAIN_SPAWN));
    assert_eq!(provider.payloads().len(), 1);
}

#[test]
fn point_aliases_name_links_outside_granted_subtrees() {
    let text = r#"permit(principal, action == SecCore::Action::"file.read", resource is SecCore::File)
when { resource.path == "/lib" || resource.path like "/lib/*" ||
    resource.path == "/usr/bin/bash" || resource.path == "/usr/bin/python3" };
permit(principal, action == SecCore::Action::"file.exec", resource is SecCore::File)
when { resource.path == "/usr/bin/python3" || resource.path like "/usr/*" };
forbid(principal, action == SecCore::Action::"file.read", resource is SecCore::File)
when { resource.path == "/usr/bin/python3" };"#;
    let resolve = |path: &str| match path {
        "/usr/bin/python3" => Some("/usr/bin/python3.11".to_owned()),
        "/lib" => Some("/usr/lib".to_owned()),
        other => Some(other.to_owned()),
    };
    // The `/lib` pair is a portable subtree grant, the exec point sits inside `/usr/*`, and a
    // forbid is the runtime protector's input: only the read point is a dead grant.
    assert_eq!(
        point_aliases(text, &resolve).unwrap(),
        ["permit #1 (file.read) grants /usr/bin/python3, which resolves to /usr/bin/python3.11"]
    );
    assert!(point_aliases(text, &|_| None).unwrap().is_empty());
}

#[test]
fn a_point_alias_is_reported_without_a_retry() {
    let root = std::env::temp_dir().join(format!("asc-intent-alias-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let root = std::fs::canonicalize(&root).unwrap();
    let (target, link) = (root.join("python3.11"), root.join("python3"));
    std::fs::write(&target, b"").unwrap();
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let policy = format!(
        r#"// [S1] report link
permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when {{ resource.path == "{}" }};"#,
        link.display()
    );
    let provider = Scripted::new(vec![Ok(body(&policy))]);
    let candidate = propose(&provider);
    std::fs::remove_dir_all(&root).unwrap();
    assert_eq!(candidate["artifact"]["text"], based(&policy));
    assert_eq!(provider.payloads().len(), 1);
    let aliases = notes(&candidate, POINT_ALIAS_NOTE);
    assert_eq!(aliases.len(), 1);
    assert!(
        aliases[0].contains(&format!("which resolves to {}", target.display())),
        "{aliases:?}"
    );
}

#[test]
fn refused_forbids_are_retried_and_reported_when_they_stay() {
    let network = format!(
        "{PLAIN_SPAWN}\n@id(\"R3\")\nforbid(principal, action == SecCore::Action::\"network.use\", resource);"
    );
    // File forbids, `@id` included, are the runtime protector's input; a network forbid is not.
    let labelled = PLAIN_SPAWN.replace("// [H1] keep the rollback package\n", "@id(\"R2\")\n");
    assert!(runtime_view_gaps(&labelled).unwrap().is_empty());
    assert_eq!(
        runtime_view_gaps(&network).unwrap(),
        [r#"forbid #3 @id("R3")"#]
    );

    let provider = Scripted::new(vec![Ok(body(&network)), Ok(body(&labelled))]);
    let candidate = propose(&provider);
    assert_eq!(candidate["artifact"]["text"], based(&labelled));
    assert!(notes(&candidate, RUNTIME_VIEW_NOTE).is_empty());
    // The retry reason numbers statements in the artifact, after the two base statements.
    assert!(provider.payloads()[1].contains(r#"forbid #5 @id("R3")"#));

    let provider = Scripted::new(vec![Ok(body(&network)), Ok(body(&network))]);
    let candidate = propose(&provider);
    assert_eq!(candidate["artifact"]["text"], based(&network));
    let runtime = notes(&candidate, RUNTIME_VIEW_NOTE);
    assert_eq!(runtime.len(), 1);
    assert!(
        runtime[0].contains("a Scope on this revision fails"),
        "{runtime:?}"
    );
}

#[test]
fn coverage_groups_statements_by_requirement_and_names_their_consumers() {
    let text = r#"@id("base")
permit(principal, action == SecCore::Action::"process.spawn", resource is SecCore::Process)
when { resource.program == "/usr/bin/bash" };
@id("R1.1")
permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/out" || resource.path like "/srv/demo/out/*" };
@id("R2")
forbid(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/previous.zip"
    && context.input.operation == SecCore::WriteOperation::"delete" };
@id("R1.2")
permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/tmp" && context.input.operation == SecCore::WriteOperation::"create" };
permit(principal, action == SecCore::Action::"file.read", resource is SecCore::File)
when { resource.path like "/*" };"#;
    assert_eq!(
        requirement_coverage(text).unwrap(),
        [
            "base    #1  sandbox, PDP",
            "R1      #2  sandbox, PDP",
            "R1      #4  sandbox only",
            "R2      #3  os-harness",
            "no @id  #5  sandbox, PDP",
        ]
    );

    let provider = Scripted::new(vec![Ok(body(PLAIN_SPAWN))]);
    let coverage = notes(&propose(&provider), COVERAGE_NOTE);
    assert_eq!(coverage.len(), 1);
    assert_eq!(
        coverage[0],
        "COVERAGE: who can carry each requirement, from statement shape only:\n  permit -> \
         sandbox + PDP (a permit testing context -> sandbox only; network.use -> PDP);\n  forbid \
         on file.read or file.write -> os-harness (any other forbid -> none).\n  A Scope still has \
         to apply it; a requirement without statements is not listed.\n  base    #1 #2  sandbox, PDP\n  \
         no @id  #3     sandbox, PDP\n  no @id  #4     os-harness"
    );
}

#[test]
fn a_network_permit_is_carried_by_the_pdp() {
    let text = r#"permit(principal, action == SecCore::Action::"network.use",
    resource == SecCore::Network::"all");"#;
    assert_eq!(requirement_coverage(text).unwrap(), ["no @id  #1  PDP"]);
}
