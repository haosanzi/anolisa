//! Exercise general intent extraction with frozen responses, checking evidence,
//! conflicts, malformed input and deadline rejection without cloud requests.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use asc_intent::{INTENT_BUDGET, IntentError, TaskInput, interpret_task};
use asc_model_client::provider::{
    FakeProvider, ModelProvider, OpenAiCompatibleProvider, ProviderError,
};
use serde_json::{Value, json};

const TASK: &str = include_str!("../../../fixtures/intent/code-review/task.json");
const DRAFT: &str = include_str!("../../../fixtures/intent/code-review/llm.json");

struct FakeClient {
    response: String,
    calls: AtomicUsize,
    fail: bool,
    delay: Duration,
}

impl FakeClient {
    fn new(content: &str) -> Self {
        Self {
            response: content.into(),
            calls: AtomicUsize::new(0),
            fail: false,
            delay: Duration::ZERO,
        }
    }
}

impl ModelProvider for FakeClient {
    fn complete(
        &self,
        model: &str,
        system: &str,
        input: &str,
        deadline: Instant,
    ) -> Result<String, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(model, "test-model");
        assert!(system.contains("This is not authorization"));
        let input: Value = serde_json::from_str(input).unwrap();
        assert!(input["task"]["text"].is_string());
        assert_eq!(input.as_object().unwrap().len(), 1);
        assert!(input.get("resource_catalog").is_none());
        for hardcoded in ["code-review", "repo-A", "readonly", "catalog"] {
            assert!(!system.contains(hardcoded));
        }
        assert!(system.lines().all(|line| line.len() <= 100));
        assert!(deadline.saturating_duration_since(Instant::now()) <= INTENT_BUDGET);
        std::thread::sleep(self.delay);
        if self.fail {
            Err(ProviderError::Transport)
        } else {
            Ok(self.response.clone())
        }
    }
}

fn task() -> TaskInput {
    serde_json::from_str(TASK).unwrap()
}
fn draft() -> Value {
    serde_json::from_str(DRAFT).unwrap()
}
fn extract(client: &FakeClient, task: &TaskInput) -> Result<Value, IntentError> {
    let outcome = interpret_task(client, "test-model", task, Instant::now() + INTENT_BUDGET)?;
    Ok(serde_json::to_value(outcome).unwrap())
}

fn add_evidence(draft: &mut Value, field: &str, quote: &str) {
    draft["evidence"]
        .as_array_mut()
        .unwrap()
        .push(json!({"field": field, "source_id": "task-input-1", "quote": quote}));
}

#[test]
fn readonly_task_yields_unconfirmed_intent_with_evidence_not_policy() {
    let client = FakeClient::new(DRAFT);
    let output = extract(&client, &task()).unwrap();
    assert_eq!(output["outcome"], "draft");
    assert_eq!(output["draft"]["status"], "DRAFT");
    assert_eq!(output["draft"]["format_version"], "asc.intent.draft.v1");
    assert_eq!(output["draft"]["prompt_version"], "intent-extraction@5");
    assert_eq!(output["draft"]["source"]["kind"], "task_text");
    assert_eq!(
        output["draft"]["intent"]["resources"]["read"],
        json!(["repo-A \u{5f53}\u{524d}\u{53d8}\u{66f4}"])
    );
    assert_eq!(
        output["draft"]["field_evidence"].as_object().unwrap().len(),
        9
    );
    assert_eq!(output["draft"]["source"]["byte_length"], task().text.len());
    assert!(output["draft"]["intent"].get("evidence").is_none());
    assert!(output.to_string().contains("quote\""));
    for field in [
        "demo",
        "skill",
        "template",
        "profile_prohibitions",
        "policy",
        "principal",
        "confirmed",
        "generation",
        "approved",
        "bundle",
    ] {
        assert!(output["draft"].get(field).is_none());
    }
    for evidence in output["draft"]["field_evidence"]
        .as_object()
        .unwrap()
        .values()
    {
        let start = usize::try_from(evidence["start_byte"].as_u64().unwrap()).unwrap();
        let end = usize::try_from(evidence["end_byte"].as_u64().unwrap()).unwrap();
        assert_eq!(task().text.get(start..end), evidence["quote"].as_str());
        assert!(
            evidence["quote_sha256"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
    }
    assert_eq!(extract(&client, &task()).unwrap(), output);
    assert_eq!(client.calls.load(Ordering::SeqCst), 2);
    let replay = interpret_task(
        &FakeProvider::new(DRAFT.into()),
        "test-model",
        &task(),
        Instant::now() + INTENT_BUDGET,
    )
    .unwrap();
    assert_eq!(serde_json::to_value(replay).unwrap(), output);
}

#[test]
fn chinese_counting_evidence_preserves_original_quotes_and_rejects_empty_goal_key() {
    let text = "当前目录下有几个文件";
    let task = TaskInput {
        source_id: "task-input-1".into(),
        text: text.into(),
    };
    let mut draft = semantic_draft(
        text,
        &json!({"read":["当前目录"],"write":[],"egress":[]}),
        &json!(["directory_listing", "metadata"]),
    );
    draft["goal"] = json!("统计当前目录直接包含的文件数量");
    draft["read_selectors"][0]["kind"] = json!("current_directory");
    let output = extract(&FakeClient::new(&draft.to_string()), &task).unwrap();
    assert_eq!(output["draft"]["field_evidence"]["/goal"]["quote"], text);
    assert_eq!(
        output["draft"]["field_evidence"]["/read_selectors/0/kind"]["quote"],
        "当前目录"
    );
    assert_eq!(
        output["draft"]["field_evidence"]["/read_selectors/0/kind"]["end_byte"],
        12
    );
    draft["evidence"][0]["field"] = json!("");
    assert!(matches!(
        extract(&FakeClient::new(&draft.to_string()), &task),
        Err(IntentError::InvalidDraft)
    ));
}

#[test]
fn side_effects_conflicting_with_user_prohibitions_require_clarification() {
    for (action, request) in [
        ("file_mutation", "fix the code"),
        ("process_execution", "run the tests"),
        ("network_access", "upload the code"),
        ("remote_publication", "publish a comment"),
    ] {
        let mut task = task();
        let quote = format!("Also {request}");
        task.text.push_str(&quote);
        task.text.push('.');
        let mut draft = draft();
        draft["requested_actions"]
            .as_array_mut()
            .unwrap()
            .push(json!(action));
        add_evidence(&mut draft, "/requested_actions/1", &quote);
        let output = extract(&FakeClient::new(&draft.to_string()), &task).unwrap();
        assert_eq!(output["outcome"], "needs_clarification");
        assert!(
            output["reasons"]
                .as_array()
                .unwrap()
                .contains(&json!("conflicting_requirements"))
        );
        assert_eq!(output["draft"]["intent"]["requested_actions"][1], action);
        assert!(output["draft"].get("profile_prohibitions").is_none());
    }
}

#[test]
fn conflicting_file_report_is_not_hidden_as_a_quality_requirement() {
    let mut task = task();
    task.text += "Save the report to report.txt.";
    let mut draft = draft();
    draft["resources"]["write"] = json!(["report.txt"]);
    add_evidence(
        &mut draft,
        "/resources/write/0",
        "Save the report to report.txt",
    );
    let output = extract(&FakeClient::new(&draft.to_string()), &task).unwrap();
    assert_eq!(output["outcome"], "needs_clarification");
    assert!(
        output["reasons"]
            .as_array()
            .unwrap()
            .contains(&json!("conflicting_requirements"))
    );
    assert_eq!(
        output["draft"]["intent"]["resources"]["write"],
        json!(["report.txt"])
    );
}

fn semantic_draft(text: &str, resources: &Value, actions: &Value) -> Value {
    let mut evidence = vec![json!({
        "field": "/goal", "source_id": "task-input-1", "quote": text
    })];
    for kind in ["read", "write", "egress"] {
        for (index, resource) in resources[kind].as_array().unwrap().iter().enumerate() {
            evidence.push(json!({
                "field": format!("/resources/{kind}/{index}"),
                "source_id": "task-input-1", "quote": resource
            }));
        }
    }
    for index in 0..actions.as_array().unwrap().len() {
        evidence.push(json!({
            "field": format!("/requested_actions/{index}"),
            "source_id": "task-input-1", "quote": text
        }));
    }
    let selectors: Vec<_> = resources["read"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(index, resource)| {
            for leaf in ["kind", "name"] {
                evidence.push(json!({
                    "field": format!("/read_selectors/{index}/{leaf}"),
                    "source_id": "task-input-1", "quote": resource
                }));
            }
            json!({"kind": "file", "name": resource})
        })
        .collect();
    json!({
        "goal": text, "resources": resources, "requested_actions": actions,
        "read_selectors": selectors,
        "prohibitions": [], "assumptions": [], "observed_only": [],
        "unresolved": [], "external_influences": [], "evidence": evidence
    })
}

#[test]
fn different_task_domains_preserve_resources_and_side_effects_without_a_profile() {
    for (text, resources, actions) in [
        (
            "Analyze sales.csv and save the report to report.txt",
            json!({"read": ["sales.csv"], "write": ["report.txt"], "egress": []}),
            json!(["read", "file_mutation"]),
        ),
        (
            "Run cleanup.sh",
            json!({"read": ["cleanup.sh"], "write": [], "egress": []}),
            json!(["process_execution"]),
        ),
        (
            "Fetch the forecast from https://weather.example/forecast",
            json!({"read": [], "write": [], "egress": ["https://weather.example/forecast"]}),
            json!(["network_access"]),
        ),
        (
            "Publish the update to #announcements",
            json!({"read": [], "write": [], "egress": ["#announcements"]}),
            json!(["remote_publication"]),
        ),
        (
            "Write a poem about spring",
            json!({"read": [], "write": [], "egress": []}),
            json!([]),
        ),
        (
            "Inspect repo-B changes using the audit skill",
            json!({"read": ["repo-B changes"], "write": [], "egress": []}),
            json!(["read"]),
        ),
    ] {
        let task = TaskInput {
            source_id: "task-input-1".into(),
            text: text.into(),
        };
        let content = semantic_draft(text, &resources, &actions);
        let output = extract(&FakeClient::new(&content.to_string()), &task).unwrap();
        assert_eq!(output["outcome"], "draft");
        assert_eq!(output["draft"]["intent"]["goal"], text);
        assert_eq!(output["draft"]["intent"]["resources"], resources);
        assert_eq!(output["draft"]["intent"]["requested_actions"], actions);
        assert_eq!(output["draft"]["intent"]["prohibitions"], json!([]));
        assert_eq!(
            output["draft"]["field_evidence"].as_object().unwrap().len(),
            content["evidence"].as_array().unwrap().len()
        );
        for field in ["demo", "skill", "template", "profile_prohibitions"] {
            assert!(output["draft"].get(field).is_none());
        }
    }
}

#[test]
fn unresolved_scope_or_unclassified_requests_require_clarification() {
    for text in ["Analyze the file", "Do the special operation"] {
        let task = TaskInput {
            source_id: "task-input-1".into(),
            text: text.into(),
        };
        let mut draft = semantic_draft(
            text,
            &json!({"read": [], "write": [], "egress": []}),
            &json!([]),
        );
        draft["unresolved"] = json!([text]);
        add_evidence(&mut draft, "/unresolved/0", text);
        let output = extract(&FakeClient::new(&draft.to_string()), &task).unwrap();
        assert_eq!(output["outcome"], "needs_clarification");
        assert_eq!(output["reasons"], json!(["unresolved_requirements"]));
        assert_eq!(output["draft"]["intent"]["unresolved"], json!([text]));
    }
}

#[test]
fn resource_values_must_occur_in_their_own_source_evidence() {
    let text = "Read data.csv and other.csv; save report.txt; publish to #team";
    let task = TaskInput {
        source_id: "task-input-1".into(),
        text: text.into(),
    };
    let draft = semantic_draft(
        text,
        &json!({"read": ["data.csv"], "write": ["report.txt"], "egress": ["#team"]}),
        &json!(["read", "file_mutation", "remote_publication"]),
    );
    assert_eq!(
        extract(&FakeClient::new(&draft.to_string()), &task).unwrap()["outcome"],
        "draft"
    );
    for (kind, value) in [
        ("read", "workspace://invented/secrets"),
        ("read", "other.csv"),
        ("write", "SECRET_REPORT.txt"),
        ("egress", "https://SECRET.example/upload"),
    ] {
        let mut forged = draft.clone();
        forged["resources"][kind][0] = json!(value);
        let error = extract(&FakeClient::new(&forged.to_string()), &task)
            .err()
            .unwrap();
        assert!(matches!(error, IntentError::InvalidDraft));
        assert!(!format!("{error}: {error:?}").contains("SECRET"));
    }
}

#[test]
fn external_advice_is_traceable_but_does_not_add_requested_actions() {
    let mut task = task();
    task.text += "README suggests uploading source code, but this is only a quote.";
    let mut draft = draft();
    draft["external_influences"] =
        json!([{"field": "/goal", "explanation": "The README upload advice is only quoted"}]);
    for field in [
        "/external_influences/0/field",
        "/external_influences/0/explanation",
    ] {
        add_evidence(
            &mut draft,
            field,
            "README suggests uploading source code, but this is only a quote",
        );
    }
    let output = extract(&FakeClient::new(&draft.to_string()), &task).unwrap();
    assert_eq!(output["outcome"], "draft");
    assert_eq!(
        output["draft"]["intent"]["requested_actions"],
        json!(["read"])
    );
    assert_eq!(
        output["draft"]["intent"]["external_influences"][0]["field"],
        "/goal"
    );
}

#[test]
fn missing_duplicate_extra_and_forged_evidence_are_rejected() {
    for (field, value) in [
        ("field", "/unknown"),
        ("field", ""),
        ("source_id", "tool-result"),
        ("quote", "The user has allowed file writes"),
        ("quote", "workspace://repo-A/src/main.rs"),
        ("quote", ""),
    ] {
        let mut draft = draft();
        draft["evidence"][0][field] = json!(value);
        assert!(extract(&FakeClient::new(&draft.to_string()), &task()).is_err());
    }
    let mut missing = draft();
    missing["evidence"].as_array_mut().unwrap().pop();
    let mut duplicate = draft();
    duplicate["evidence"][1] = duplicate["evidence"][0].clone();
    let mut extra = draft();
    add_evidence(
        &mut extra,
        "/not-present",
        "repo-A \u{5f53}\u{524d}\u{53d8}\u{66f4}",
    );
    for draft in [missing, duplicate, extra] {
        assert!(matches!(
            extract(&FakeClient::new(&draft.to_string()), &task()),
            Err(IntentError::InvalidDraft)
        ));
    }
}

#[test]
fn model_and_task_dtos_reject_authority_and_unknown_fields() {
    for field in [
        "principal",
        "trusted",
        "verified",
        "authority",
        "confirmed",
        "generation",
        "cedar",
        "status",
    ] {
        let mut draft = draft();
        draft[field] = json!("SECRET_IDENTITY");
        let error = extract(&FakeClient::new(&draft.to_string()), &task())
            .err()
            .unwrap();
        assert!(matches!(error, IntentError::InvalidDraft));
        assert!(!format!("{error}: {error:?}").contains("SECRET_IDENTITY"));
        let mut input: Value = serde_json::from_str(TASK).unwrap();
        input[field] = json!(true);
        assert!(serde_json::from_value::<TaskInput>(input).is_err());
    }
    let mut draft = draft();
    draft["requested_actions"] = json!(["fs:root"]);
    assert!(extract(&FakeClient::new(&draft.to_string()), &task()).is_err());
    let duplicate = DRAFT.replacen("\"goal\":", "\"goal\": \"duplicate\", \"goal\":", 1);
    assert!(extract(&FakeClient::new(&duplicate), &task()).is_err());
}

#[test]
#[ignore = "requires DASHSCOPE_API_KEY and makes one billable cloud request"]
fn dashscope_readonly_fixture() {
    let task = task();
    let provider = OpenAiCompatibleProvider::new(
        "https://dashscope.aliyuncs.com/compatible-mode/v1",
        std::env::var("DASHSCOPE_API_KEY")
            .unwrap_or_else(|_| panic!("DASHSCOPE_API_KEY is required")),
    )
    .unwrap();
    let outcome = interpret_task(
        &provider,
        "qwen-plus",
        &task,
        Instant::now() + INTENT_BUDGET,
    )
    .unwrap();
    let output = serde_json::to_value(outcome).unwrap();
    assert_eq!(output["outcome"], "draft");
    assert_eq!(
        output["draft"]["intent"]["resources"]["read"],
        json!(["repo-A \u{5f53}\u{524d}\u{53d8}\u{66f4}"])
    );
    assert_eq!(output["draft"]["intent"]["resources"]["write"], json!([]));
    assert_eq!(output["draft"]["intent"]["resources"]["egress"], json!([]));
    assert_eq!(
        output["draft"]["intent"]["requested_actions"],
        json!(["read"])
    );
    for action in [
        "file_mutation",
        "process_execution",
        "network_access",
        "remote_publication",
    ] {
        assert!(
            output["draft"]["intent"]["prohibitions"]
                .as_array()
                .unwrap()
                .contains(&json!(action))
        );
    }
    assert_eq!(
        output["draft"]["field_evidence"].as_object().unwrap().len(),
        9
    );
}

#[test]
fn selectors_reject_missing_extra_forged_and_unclassified_scope() {
    for selectors in [
        json!([]),
        json!([{"kind": "unknown", "name": "repo-A"}]),
        json!([{"kind": "file"}]),
        json!([{"kind": "changes", "name": "repo-B"}]),
        json!([{"kind": "changes", "name": "repo-A", "trusted": true}]),
        json!([{"kind": "changes", "name": "repo-A"}, {"kind": "changes"}]),
    ] {
        let mut forged = draft();
        forged["read_selectors"] = selectors;
        assert!(matches!(
            extract(&FakeClient::new(&forged.to_string()), &task()),
            Err(IntentError::InvalidDraft)
        ));
    }
    for leaf in ["kind", "name"] {
        let mut forged = draft();
        let evidence = forged["evidence"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["field"] == format!("/read_selectors/0/{leaf}"))
            .unwrap();
        evidence["quote"] = json!("\u{4e0d}\u{8981}\u{8054}\u{7f51}");
        assert!(matches!(
            extract(&FakeClient::new(&forged.to_string()), &task()),
            Err(IntentError::InvalidDraft)
        ));
    }
}

#[test]
fn oversized_or_malformed_model_content_fails() {
    for content in [String::new(), "not JSON".into(), "x".repeat(16 * 1024 + 1)] {
        assert!(extract(&FakeClient::new(&content), &task()).is_err());
    }
}

#[test]
fn invalid_input_expiry_and_model_failures_never_return_an_old_draft() {
    let mut client = FakeClient::new(DRAFT);
    assert!(interpret_task(&client, "test-model", &task(), Instant::now()).is_err());
    for text in [String::new(), " ".into(), "x".repeat(64 * 1024 + 1)] {
        let invalid = TaskInput {
            source_id: "task-input-1".into(),
            text,
        };
        assert!(matches!(
            extract(&client, &invalid),
            Err(IntentError::InvalidInput)
        ));
    }
    assert_eq!(client.calls.load(Ordering::SeqCst), 0);
    client.fail = true;
    let error = extract(&client, &task()).err().unwrap();
    assert!(matches!(
        error,
        IntentError::Provider(ProviderError::Transport)
    ));
    assert_eq!(
        error.to_string(),
        "intent extraction provider failed: model request failed"
    );
    assert!(!format!("{error:?}").contains("SECRET_"));
    client.fail = false;
    client.delay = Duration::from_millis(20);
    assert!(matches!(
        interpret_task(
            &client,
            "test-model",
            &task(),
            Instant::now() + Duration::from_millis(5)
        ),
        Err(IntentError::DeadlineExceeded)
    ));
}
