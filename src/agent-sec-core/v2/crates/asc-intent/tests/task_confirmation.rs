//! A task may ask that a permission be confirmed before each execution. The confirmation only
//! counts when the policy already grants the same paths to the same action, so the generator
//! admits the one advice contract, retries a confirmation that would widen authorization, and
//! names every admitted gate with the paths and the message a prompt will show.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use asc_intent::{
    HUMAN_GATE_NOTE, PolicyError, ProposalContext, ProposalOutcome, TaskInput, confirmation_gaps,
    human_gates, prepare_policy, prepare_task_policy, propose_task,
};
use asc_model_client::provider::{ModelProvider, ProviderError};
use serde_json::{Value, json};

/// Writes everything under `out/`, as a task that only names `out/` in its goal would.
const GOAL: &str = r#"@id("goal")
permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/out" || resource.path like "/srv/demo/out/*" };"#;

/// Asks before writing `out/`, which the goal already grants: friction, not a wider grant.
const GATED_OUT: &str = r#"@id("R2")
@advice("{\"verdict\":\"escalate\",\"message\":\"out/ 下的产物每次都要先问我\"}")
permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/out" || resource.path like "/srv/demo/out/*" };"#;

/// Asks before writing a directory no other permit grants.
const GATED_CONFIG: &str = r#"@id("R2")
@advice("{\"verdict\":\"escalate\",\"message\":\"config/ 是手工维护的，改动前需要你确认\"}")
permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/config" || resource.path like "/srv/demo/config/*" };"#;

const PLAIN_CONFIG: &str = r#"@id("goal")
permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/config" || resource.path like "/srv/demo/config/*" };"#;

fn body(policy: &str) -> String {
    json!({"policy": policy, "unresolved": []}).to_string()
}

fn gate(text: &str) -> String {
    format!("{GOAL}\n{text}")
}

struct Scripted {
    responses: std::sync::Mutex<VecDeque<Result<String, ProviderError>>>,
    payloads: std::sync::Mutex<Vec<String>>,
}

impl Scripted {
    fn new(responses: Vec<Result<String, ProviderError>>) -> Self {
        Self {
            responses: std::sync::Mutex::new(responses.into()),
            payloads: std::sync::Mutex::new(Vec::new()),
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
fn a_gate_on_granted_paths_is_admitted_and_named() {
    let text = gate(GATED_OUT);
    let artifact = prepare_task_policy(&text).unwrap();
    assert!(confirmation_gaps(&artifact.text).unwrap().is_empty());
    let gates = human_gates(&artifact.text).unwrap();
    assert_eq!(gates.len(), 1);
    assert_eq!(gates[0].requirement, "R2");
    // A directory pair names one location, and that is what the prompt shows.
    assert_eq!(gates[0].paths, ["/srv/demo/out"]);
    assert_eq!(gates[0].message, "out/ 下的产物每次都要先问我");
    // Statements are numbered in the published artifact, after the base read and the bash launch.
    assert_eq!(gates[0].position, 4);
    // A command proposal grants one launch and keeps its own approval flow: no gate there.
    assert!(matches!(
        prepare_policy(&text),
        Err(PolicyError::UnsupportedPolicy)
    ));
}

#[test]
fn a_gate_outside_every_other_grant_is_widening() {
    let text = gate(GATED_CONFIG);
    let artifact = prepare_task_policy(&text).unwrap();
    assert_eq!(
        confirmation_gaps(&artifact.text).unwrap(),
        [
            r#"permit #4 @id("R2") asks before acting on /srv/demo/config, which no other permit grants (file.write), so the confirmation would widen authorization"#,
        ]
    );
    // Granting the same location first turns the same statement into a confirmation.
    assert!(
        confirmation_gaps(&gate(&format!("{PLAIN_CONFIG}\n{GATED_CONFIG}")))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_gate_that_tests_context_is_never_shown() {
    let text = gate(
        r#"@id("R2")
@advice("{\"verdict\":\"escalate\",\"message\":\"每次都要先问我\"}")
permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/out"
    && context.input.operation == SecCore::WriteOperation::"create" };"#,
    );
    let gaps = confirmation_gaps(&text).unwrap();
    assert_eq!(gaps.len(), 1);
    assert!(
        gaps[0].contains("no confirmation is ever shown"),
        "{gaps:?}"
    );
}

#[test]
fn a_gate_must_name_exactly_one_action_and_a_path() {
    // One action and one path are what an approval prompt can show; anything else is not a gate.
    let many = gate(
        r#"@id("R2")
@advice("{\"verdict\":\"escalate\",\"message\":\"先问我\"}")
permit(principal,
  action in [SecCore::Action::"file.write", SecCore::Action::"file.read"],
  resource is SecCore::File)
when { resource.path == "/srv/demo/out" };"#,
    );
    let mut gaps = confirmation_gaps(&many).unwrap();
    assert_eq!(gaps.len(), 1);
    assert!(
        gaps[0].contains("without naming exactly one action"),
        "{gaps:?}"
    );

    let pathless = gate(
        r#"@id("R2")
@advice("{\"verdict\":\"escalate\",\"message\":\"先问我\"}")
permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File);"#,
    );
    gaps = confirmation_gaps(&pathless).unwrap();
    assert_eq!(gaps.len(), 1);
    assert!(gaps[0].contains("without naming a path"), "{gaps:?}");
}

#[test]
fn only_one_escalation_contract_is_admitted() {
    for rejected in [
        // A forbid cannot carry a confirmation: it is already the stricter answer.
        r#"@id("R1")
@advice("{\"verdict\":\"escalate\",\"message\":\"先问我\"}")
forbid(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/out" };"#,
        // No decision surface reads `warn` back to a human on this path.
        r#"@id("R1")
@advice("{\"verdict\":\"warn\",\"message\":\"先问我\"}")
permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/out" };"#,
        // A prompt with no reason explains nothing, so the gate is not admitted.
        r#"@id("R1")
@advice("{\"verdict\":\"escalate\"}")
permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/out" };"#,
        // A task may not choose how its command is rewritten.
        r#"@id("R1")
@advice("{\"verdict\":\"escalate\",\"message\":\"先问我\",\"transform\":\"$target.x\"}")
permit(principal, action == SecCore::Action::"file.write", resource is SecCore::File)
when { resource.path == "/srv/demo/out" };"#,
    ] {
        assert!(matches!(
            prepare_task_policy(&gate(rejected)),
            Err(PolicyError::UnsupportedPolicy | PolicyError::Advice)
        ));
    }
}

#[test]
fn a_widening_gate_is_retried_with_the_reason() {
    // The first draft asks about `config/` without granting it; the repair grants `config/` in the
    // goal and keeps the confirmation on `out/`, which the goal already granted.
    let repaired = format!("{GOAL}\n{PLAIN_CONFIG}\n{GATED_OUT}");
    let provider = Scripted::new(vec![Ok(body(&gate(GATED_CONFIG))), Ok(body(&repaired))]);
    let candidate = propose(&provider);
    assert_eq!(candidate["draft"]["policy"], repaired);
    let payloads = provider.payloads();
    assert_eq!(payloads.len(), 2);
    assert!(
        payloads[1].contains("would widen authorization"),
        "{payloads:?}"
    );
    let gates = notes(&candidate, HUMAN_GATE_NOTE);
    assert_eq!(gates.len(), 1);
    assert!(
        gates[0].contains("friction and not a wider grant"),
        "{gates:?}"
    );
}

#[test]
fn a_widening_gate_that_stays_is_reported_as_unpublishable() {
    let provider = Scripted::new(vec![
        Ok(body(&gate(GATED_CONFIG))),
        Ok(body(&gate(GATED_CONFIG))),
    ]);
    let candidate = propose(&provider);
    assert_eq!(provider.payloads().len(), 2);
    let gates = notes(&candidate, HUMAN_GATE_NOTE);
    assert_eq!(gates.len(), 1);
    assert!(gates[0].contains("would widen authorization"), "{gates:?}");
    assert!(
        gates[0].contains("Do not publish this revision"),
        "{gates:?}"
    );
}

#[test]
fn an_admitted_gate_travels_with_its_paths_and_message() {
    let provider = Scripted::new(vec![Ok(body(&gate(GATED_OUT)))]);
    let candidate = propose(&provider);
    assert_eq!(provider.payloads().len(), 1);
    let gates = notes(&candidate, HUMAN_GATE_NOTE);
    assert_eq!(
        gates,
        [format!(
            "{HUMAN_GATE_NOTE} these permits stop for confirmation before taking effect. A path \
             listed here is also granted by another permit of the same action, so the gate is \
             friction and not a wider grant; a network.use gate is the whole-network grant itself, \
             so nothing is allowed without confirming it:\n  \
             #4 @id(\"R2\") /srv/demo/out -- out/ 下的产物每次都要先问我"
        )]
    );
}

/// Asks before every network use, on the only shape the schema has for it.
const GATED_NETWORK: &str = r#"@id("R2")
@advice("{\"verdict\":\"escalate\",\"message\":\"允许本次命令联网？\"}")
permit(principal, action == SecCore::Action::"network.use",
       resource == SecCore::Network::"all");"#;

#[test]
fn a_whole_network_gate_needs_no_other_grant() {
    // Network has no path or endpoint dimension, so nothing narrower can grant it first; the gate
    // is the task's own "ask before each use" and still never allows silently.
    let artifact = prepare_task_policy(GATED_NETWORK).unwrap();
    assert!(confirmation_gaps(&artifact.text).unwrap().is_empty());
    let gates = human_gates(&artifact.text).unwrap();
    assert_eq!(gates.len(), 1);
    assert_eq!(gates[0].requirement, "R2");
    assert!(gates[0].paths.is_empty());
    assert_eq!(gates[0].message, "允许本次命令联网？");

    let provider = Scripted::new(vec![Ok(body(GATED_NETWORK))]);
    let candidate = propose(&provider);
    let gates = notes(&candidate, HUMAN_GATE_NOTE);
    assert_eq!(gates.len(), 1);
    assert!(
        gates[0].contains("#3 @id(\"R2\") network.use -- 允许本次命令联网？"),
        "{gates:?}"
    );
    let coverage = notes(&candidate, "COVERAGE:");
    assert_eq!(coverage.len(), 1);
    assert!(coverage[0].ends_with("  R2    #3     PDP"), "{coverage:?}");
}
