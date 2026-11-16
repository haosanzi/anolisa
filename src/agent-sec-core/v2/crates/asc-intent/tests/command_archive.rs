//! Archive commands keep the file roles their program performs, whatever the model omits.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use asc_intent::{CommandInput, CommandPolicyOutcome, propose_command};
use asc_model_client::provider::{ModelProvider, ProviderError};
use serde_json::json;

/// One model answer, replayed for every call so the assertions see a fixed draft.
struct Draft(String);

impl ModelProvider for Draft {
    fn complete(&self, _: &str, _: &str, _: &str, _: Instant) -> Result<String, ProviderError> {
        Ok(self.0.clone())
    }
}

/// Records the payloads so a test can assert the model saw the raw command.
#[derive(Default)]
struct Recording(Mutex<Vec<String>>);

impl ModelProvider for Recording {
    fn complete(
        &self,
        _: &str,
        _: &str,
        payload: &str,
        _: Instant,
    ) -> Result<String, ProviderError> {
        self.0.lock().unwrap().push(payload.to_owned());
        Ok(json!({"policy": "", "unresolved": []}).to_string())
    }
}

fn input(command: &str) -> CommandInput {
    CommandInput {
        command: command.into(),
        cwd: "/work".into(),
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn candidate(provider: &dyn ModelProvider, command: &str) -> (String, Vec<String>) {
    let outcome = propose_command(provider, "fixture", &input(command), deadline()).unwrap();
    let CommandPolicyOutcome::Candidate { policy, caveats } = outcome else {
        panic!("expected a candidate");
    };
    asc_intent::prepare_policy(&policy).expect("the union is admitted");
    (policy, caveats)
}

#[test]
fn a_draft_without_the_archive_roles_gains_read_and_write() {
    // What the model actually returned for this command once: no file right at all, one exec
    // target it invented under the cwd, and the archive described only in a caveat.
    let draft = json!({
        "policy": "permit(principal, action == SecCore::Action::\"file.exec\", resource is SecCore::File) when { resource.path == \"/work/tar\" };",
        "unresolved": [],
        "caveats": ["tar reads the source subtree and writes the archive; both happen inside tar"],
    })
    .to_string();
    let (policy, caveats) = candidate(&Draft(draft), "tar -czf /work/out.tgz -C /work/repo .");
    assert!(
        policy.contains("resource.path == \"/work/repo\" || resource.path like \"/work/repo/*\""),
        "{policy}"
    );
    assert!(
        policy.contains("resource.path == \"/work\" || resource.path like \"/work/*\""),
        "{policy}"
    );
    assert!(
        policy.contains("SecCore::Action::\"file.write\""),
        "{policy}"
    );
    // The model text stays where it was, and the reason for the directory write is reviewable.
    assert!(
        policy.starts_with("permit(principal, action == SecCore::Action::\"file.exec\""),
        "{policy}"
    );
    assert!(
        caveats
            .iter()
            .any(|caveat| caveat.contains("deterministic archive roles")),
        "{caveats:?}"
    );
    assert_eq!(caveats.len(), 2, "{caveats:?}");
}

#[test]
fn a_draft_that_names_the_archive_loses_it_and_gains_the_directory() {
    // The better of the two probes granted the archive file rather than its directory. The file
    // exists only after the command writes it, so a rule naming it cannot be resolved before the
    // launch; the directory grant the grammar adds is what creates it.
    let draft = json!({
        "policy": "permit(principal, action == SecCore::Action::\"file.read\", resource is SecCore::File) when { resource.path like \"/work/repo/*\" }; \
                   permit(principal, action == SecCore::Action::\"file.write\", resource is SecCore::File) when { resource.path == \"/work/out.tgz\" };",
        "unresolved": [],
        "caveats": [],
    })
    .to_string();
    let (policy, caveats) = candidate(&Draft(draft), "tar -czf /work/out.tgz -C /work/repo .");
    assert!(!policy.contains("/work/out.tgz"), "{policy}");
    assert!(
        policy.contains("resource.path == \"/work\" || resource.path like \"/work/*\""),
        "{policy}"
    );
    // A statement naming something that exists stays, re-rendered by the official parser.
    assert!(
        policy.contains("resource.path like \"/work/repo/*\""),
        "{policy}"
    );
    assert_eq!(caveats.len(), 2, "{caveats:?}");
    assert!(
        caveats
            .iter()
            .any(|caveat| caveat.contains("dropped 1 rule(s) naming the archive (/work/out.tgz)")),
        "{caveats:?}"
    );
}

#[test]
fn a_draft_that_never_names_the_archive_keeps_its_text_verbatim() {
    let policy = "permit(principal, action == SecCore::Action::\"file.read\", resource is SecCore::File) when { resource.path == \"/work/one.txt\" };";
    let draft = json!({
        "policy": policy,
        "unresolved": [],
        "caveats": [],
    })
    .to_string();
    let (actual, caveats) = candidate(&Draft(draft), "tar -czf out.tgz one.txt");
    assert!(actual.starts_with(policy), "{actual}");
    assert_eq!(caveats.len(), 1, "{caveats:?}");
}

#[test]
fn a_command_outside_the_fixed_grammar_keeps_the_draft_byte_for_byte() {
    let policy = "permit(principal, action == SecCore::Action::\"file.read\", resource is SecCore::File) when { resource.path == \"/work/a.csv\" };";
    let draft = json!({
        "policy": policy,
        "unresolved": [],
        "caveats": ["one caveat"],
    })
    .to_string();
    let (actual, caveats) = candidate(&Draft(draft), "cat a.csv");
    assert_eq!(actual, policy);
    assert_eq!(caveats, vec!["one caveat".to_owned()]);
}

#[test]
fn an_unreadable_archive_command_keeps_the_draft() {
    let draft = json!({
        "policy": "permit(principal, action == SecCore::Action::\"process.spawn\", resource is SecCore::Process) when { resource.program == \"tar\" };",
        "unresolved": [],
        "caveats": [],
    })
    .to_string();
    let parsed: serde_json::Value = serde_json::from_str(&draft).unwrap();
    let expected = parsed["policy"].as_str().unwrap().to_owned();
    let (policy, caveats) = candidate(&Draft(draft), "tar -czf out.tgz -C $DIR .");
    assert_eq!(policy, expected);
    assert!(caveats.is_empty(), "{caveats:?}");
}

#[test]
fn the_model_payload_still_carries_the_raw_command() {
    let payloads = Recording::default();
    let _ = candidate(&payloads, "tar -czf out.tgz -C repo .");
    let payloads = payloads.0.lock().unwrap();
    assert_eq!(payloads.len(), 1);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&payloads[0]).unwrap(),
        json!({"command": "tar -czf out.tgz -C repo .", "cwd": "/work"})
    );
}
