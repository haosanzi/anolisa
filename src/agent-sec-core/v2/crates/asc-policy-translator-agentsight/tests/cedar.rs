use asc_policy_translator_agentsight::{
    AgentSightBindingPlan, AgentSightTranslator, FILE_PROTECTION_POLICY_MEDIA_TYPE,
};
use asc_policy_types::{binding::PreparedBinding, target::TranslationOutcome};
use serde_json::{Value, json};

fn binding(text: &str) -> PreparedBinding {
    let mut binding: PreparedBinding = serde_json::from_str(include_str!(
        "../../asc-policy-types/tests/fixtures/prepared-binding.json"
    ))
    .unwrap();
    binding.policy.template = serde_json::from_value(json!({"language":"cedar","content":{
        "schema":{"schemaId":"seccore.system","revision":1},"text":text
    }}))
    .unwrap();
    binding
}

fn rule(condition: &str) -> String {
    format!(
        "forbid(principal, action == SecCore::Action::\"file.write\", resource is SecCore::File) when {{ {condition} }};"
    )
}

fn read_rule(condition: &str) -> String {
    format!(
        "forbid(principal, action == SecCore::Action::\"file.read\", resource is SecCore::File) when {{ {condition} }};"
    )
}

fn translate(text: &str) -> Value {
    let TranslationOutcome::Translated(plan) =
        AgentSightTranslator.translate(&binding(text)).unwrap()
    else {
        panic!("expected structured policy: {text}");
    };
    let plan: AgentSightBindingPlan = serde_json::from_slice(&plan.content).unwrap();
    assert_eq!(plan.policy.media_type, FILE_PROTECTION_POLICY_MEDIA_TYPE);
    serde_json::from_str(&plan.policy.content).unwrap()
}

#[test]
fn delete_and_write_keep_independent_scopes_and_merge_identical_targets() {
    let text = format!(
        "{}{}{}",
        rule(
            r#"context.input.operation == SecCore::WriteOperation::"delete" && resource.path == "/config""#
        ),
        rule(
            r#"context.input.operation == SecCore::WriteOperation::"write" && resource.path == "/config""#
        ),
        rule(
            r#"context.input.operation == SecCore::WriteOperation::"delete" && resource.path == "/workspace""#
        )
    );
    let policy = translate(&text);
    assert_eq!(policy["version"], 1);
    assert_eq!(policy["targets"].as_array().unwrap().len(), 2);
    assert_eq!(
        policy["targets"][0]["protections"],
        json!({"delete":true,"ordinary_write":true})
    );
    assert_eq!(
        policy["targets"][1]["protections"],
        json!({"delete":true,"ordinary_write":false})
    );
    assert_eq!(translate(&text), policy);
}

#[test]
fn read_denial_preserves_exact_targets_and_merges_independent_protections() {
    let read = read_rule(r#"resource.path == "/secret""#);
    assert_eq!(
        translate(&read)["targets"][0],
        json!({"path":"/secret","kind":"exact_file",
            "protections":{"delete":false,"ordinary_write":false,"read":true},"exclusions":[]})
    );
    let write = rule(
        r#"[SecCore::WriteOperation::"write", SecCore::WriteOperation::"delete"].contains(context.input.operation) && resource.path == "/secret""#,
    );
    let policy = translate(&format!("{read}{write}"));
    assert_eq!(policy["targets"].as_array().unwrap().len(), 1);
    assert_eq!(
        policy["targets"][0]["protections"],
        json!({"delete":true,"ordinary_write":true,"read":true})
    );
    assert_eq!(translate(&format!("{write}{read}")), policy);

    let policy = translate(
        r#"forbid(principal, action in [SecCore::Action::"file.read"], resource)
        when { ["/secret", "/public"].contains(resource.path) || resource.path == "/other" }
        unless { resource.path != "/secret" };"#,
    );
    assert_eq!(policy, translate(&read));
}

#[test]
fn unsupported_read_scopes_and_conditions_reject_the_whole_policy() {
    let supported = rule(
        r#"context.input.operation == SecCore::WriteOperation::"delete" && resource.path == "/safe""#,
    );
    for (condition, code) in [
        (
            r#"resource.path == "/secrets" || resource.path like "/secrets/*""#,
            "UNSUPPORTED_READ_TARGET",
        ),
        (r#"resource.path != "/public""#, "UNBOUNDED_PATH_SCOPE"),
        (
            r#"resource.path == "/secret" && context.input.program == "/bin/cat""#,
            "UNSUPPORTED_CONDITION",
        ),
    ] {
        let TranslationOutcome::Rejected(error) = AgentSightTranslator
            .translate(&binding(&format!("{supported}{}", read_rule(condition))))
            .unwrap()
        else {
            panic!("must reject unsupported read constraint: {condition}");
        };
        assert_eq!(error.code, format!("CEDAR_RULE_1_{code}"));
    }
    let mixed = r#"forbid(principal, action in [SecCore::Action::"file.read", SecCore::Action::"file.write"], resource)
        when { resource.path == "/secret" };"#;
    assert!(matches!(
        AgentSightTranslator.translate(&binding(mixed)).unwrap(),
        TranslationOutcome::Rejected(_)
    ));
}

#[test]
fn literal_sets_and_unless_preserve_directory_and_entry_exclusions() {
    let text = r#"forbid(principal, action in [SecCore::Action::"file.write"], resource)
        when { [SecCore::WriteOperation::"write", SecCore::WriteOperation::"delete"].contains(context.input.operation)
            && (resource.path == "/workspace" || resource.path like "/workspace/*") }
        unless { resource.path == "/workspace/cache" || resource.path like "/workspace/cache/*"
            || ["/workspace/a", "/workspace/b"].contains(resource.path) };"#;
    let policy = translate(text);
    assert_eq!(policy["targets"].as_array().unwrap().len(), 1);
    let target = &policy["targets"][0];
    assert_eq!(target["kind"], "directory_tree");
    assert_eq!(target["exclusions"].as_array().unwrap().len(), 3);
    assert_eq!(target["exclusions"][0]["kind"], "exact_entry");
    assert_eq!(target["exclusions"][2]["kind"], "directory_subtree");
    assert_eq!(
        target["protections"],
        json!({"delete":true,"ordinary_write":true})
    );
}

#[test]
fn structured_output_matches_the_clients_v1_contract_fixture() {
    let source = r#"
        forbid(principal, action == SecCore::Action::"file.write", resource)
        when { context.input.operation == SecCore::WriteOperation::"write" && resource.path == "/config" };
        forbid(principal, action == SecCore::Action::"file.write", resource)
        when { [SecCore::WriteOperation::"delete", SecCore::WriteOperation::"write"].contains(context.input.operation)
            && (resource.path == "/workspace" || resource.path like "/workspace/*") }
        unless { resource.path == "/workspace/cache" || resource.path like "/workspace/cache/*"
            || resource.path == "/workspace/state" };
    "#;
    let expected: Value = serde_json::from_str(include_str!(
        "../../../fixtures/clients/agentsight/file-protection-v1.json"
    ))
    .unwrap();
    assert_eq!(translate(source), expected);
}

#[test]
fn permit_rules_do_not_change_the_forbid_projection() {
    let forbids = format!(
        "{}{}",
        read_rule(r#"resource.path == "/secret""#),
        rule(
            r#"context.input.operation == SecCore::WriteOperation::"delete"
            && (resource.path == "/workspace" || resource.path like "/workspace/*")"#
        )
    );
    let expected = translate(&forbids);
    let permits = [
        r#"permit(principal, action == SecCore::Action::"file.read", resource)
            when { resource.path == "/secret" };"#,
        r#"permit(principal, action == SecCore::Action::"file.write", resource)
            when { resource.path == "/workspace" || resource.path like "/workspace/*" };"#,
        r#"permit(principal, action == SecCore::Action::"file.exec", resource)
            when { resource.path == "/usr/bin/python3" };"#,
        r#"permit(principal, action == SecCore::Action::"network.use", resource);"#,
        r#"@id("tool-permit") @advice("{\"verdict\":\"escalate\"}")
            permit(principal == SecCore::Subject::"worker",
                action == SecCore::Action::"process.spawn", resource is SecCore::Process)
            when { context.input.cwd == "/workspace"
                && resource.resolved_program == "/usr/bin/python3" };"#,
    ];
    for permit in permits {
        for source in [format!("{permit}{forbids}"), format!("{forbids}{permit}")] {
            assert_eq!(translate(&source), expected, "{permit}");
        }
    }
    assert_eq!(
        translate(&format!("{}{forbids}", permits.join("\n"))),
        expected
    );
}

#[test]
fn permit_only_policy_rejects_an_empty_effective_plan() {
    let source = r#"permit(principal, action == SecCore::Action::"file.write", resource);"#;
    let TranslationOutcome::Rejected(error) =
        AgentSightTranslator.translate(&binding(source)).unwrap()
    else {
        panic!("permit-only policy must not produce an enforcement plan");
    };
    assert_eq!(error.code, "CEDAR_EMPTY_EFFECTIVE_POLICY");
}

#[test]
fn skipped_permits_still_require_frontend_validation() {
    let forbid = read_rule(r#"resource.path == "/secret""#);
    for permit in [
        r#"permit(principal, action == SecCore::Action::"unknown", resource);"#,
        r#"@unknown("ignored") permit(principal, action == SecCore::Action::"file.read", resource);"#,
    ] {
        let TranslationOutcome::Rejected(error) = AgentSightTranslator
            .translate(&binding(&format!("{permit}{forbid}")))
            .unwrap()
        else {
            panic!("invalid permit must reject the whole source: {permit}");
        };
        assert_eq!(error.code, "INVALID_CEDAR_POLICY");
    }
}

#[test]
fn permits_do_not_hide_unsupported_forbids_or_change_diagnostic_positions() {
    let permit = r#"permit(principal, action == SecCore::Action::"file.write", resource);"#;
    let supported = read_rule(r#"resource.path == "/secret""#);
    let unsupported = rule(
        r#"context.input.operation == SecCore::WriteOperation::"delete"
            && context.input.program == "/usr/bin/rm" && resource.path == "/workspace""#,
    );
    for (source, index) in [
        (format!("{permit}{supported}{unsupported}"), 2),
        (format!("{unsupported}{permit}{supported}"), 0),
    ] {
        let TranslationOutcome::Rejected(error) =
            AgentSightTranslator.translate(&binding(&source)).unwrap()
        else {
            panic!("unsupported forbid must reject the whole source");
        };
        assert_eq!(
            error.code,
            format!("CEDAR_RULE_{index}_UNSUPPORTED_CONDITION")
        );
    }
}

#[test]
fn unsupported_conditions_reject_the_whole_policy_including_later_statements() {
    let supported = rule(
        r#"context.input.operation == SecCore::WriteOperation::"delete" && resource.path == "/safe""#,
    );
    for condition in [
        r#"context.input.operation == SecCore::WriteOperation::"delete" && context.input.program == "/usr/bin/rm" && resource.path == "/a""#,
        r#"context.input.operation == SecCore::WriteOperation::"rename" && resource.path == "/a""#,
        r#"context.input.operation == SecCore::WriteOperation::"create" && resource.path == "/a""#,
        r#"context.input.operation == SecCore::WriteOperation::"setattr" && context.input has mode && context.input.mode == 0 && resource.path == "/a""#,
        r#"context.input.operation == SecCore::WriteOperation::"write" && resource.path like "/workspace/*""#,
        r#"context.input.operation == SecCore::WriteOperation::"write" && resource.path like "/workspace/*.log""#,
        r#"context.input.operation == SecCore::WriteOperation::"write" && resource.path == "relative""#,
        r#"context.input.operation == SecCore::WriteOperation::"write" && resource.path == "/a/../b""#,
        r#"context.input.operation != SecCore::WriteOperation::"write" && resource.path == "/a""#,
        r#"resource.path == "/a""#,
    ] {
        let outcome = AgentSightTranslator
            .translate(&binding(&format!("{supported}{}", rule(condition))))
            .unwrap();
        let TranslationOutcome::Rejected(error) = outcome else {
            panic!("must reject {condition}");
        };
        assert!(error.code.starts_with("CEDAR_RULE_1_"), "{}", error.code);
    }
    for text in [
        rule(r#"false && context.input.program == "/usr/bin/rm""#),
        rule("[].contains(context.input.program)"),
        supported.replace("resource is SecCore::File)", "resource == SecCore::File::\"a\")"),
        "forbid(principal, action == SecCore::Action::\"file.exec\", resource) when { resource.path == \"/a\" };".into(),
    ] {
        assert!(matches!(AgentSightTranslator.translate(&binding(&text)).unwrap(), TranslationOutcome::Rejected(_)));
    }
}

#[test]
fn runtime_only_forbids_reject_the_whole_agentsight_binding() {
    let base = rule(
        r#"context.input.operation == SecCore::WriteOperation::"write" && resource.path == "/config""#,
    );
    for runtime_rule in [
        base.replace(
            "forbid(principal,",
            r#"forbid(principal == SecCore::Subject::"worker","#,
        ),
        base.replace(
            "when {",
            r#"when { principal == SecCore::Subject::"worker" &&"#,
        ),
        format!(r#"@id("protected") {base}"#),
    ] {
        let combined = format!("{base}\n{runtime_rule}");
        let input = binding(&combined);
        let asc_policy_types::authoring::PolicySource::Cedar(source) = &input.policy.template
        else {
            unreachable!()
        };
        asc_policy_cedar::validate(source).unwrap();
        assert!(
            matches!(
                AgentSightTranslator.translate(&input).unwrap(),
                TranslationOutcome::Rejected(_)
            ),
            "{runtime_rule}"
        );
    }
}

#[test]
fn conflicts_limits_empty_output_and_unknown_schema_fail_without_a_plan() {
    let base = r#"context.input.operation == SecCore::WriteOperation::"write" && (resource.path == "/a" || resource.path like "/a/*")"#;
    for text in [
        format!(
            "{}{}",
            rule(base),
            rule(&format!("{base} && resource.path != \"/a/cache\""))
        ),
        rule(&format!("{base} && resource.path != \"/a\"")),
        rule(&format!("{base} && false")),
        rule(&format!(
            r#"context.input.operation == SecCore::WriteOperation::"write" && [{}].contains(resource.path)"#,
            (0..65)
                .map(|i| format!("\"/file{i}\""))
                .collect::<Vec<_>>()
                .join(",")
        )),
    ] {
        assert!(
            matches!(
                AgentSightTranslator.translate(&binding(&text)).unwrap(),
                TranslationOutcome::Rejected(_)
            ),
            "{text}"
        );
    }
    let mut input = binding(&rule(base));
    let asc_policy_types::authoring::PolicySource::Cedar(source) = &mut input.policy.template
    else {
        unreachable!()
    };
    source.schema.revision = asc_policy_types::identifiers::Revision::new(3).unwrap();
    assert!(matches!(
        AgentSightTranslator.translate(&input).unwrap(),
        TranslationOutcome::Rejected(_)
    ));
}

#[test]
fn boolean_lowering_matches_cedar_for_supported_request_conditions() {
    let source = r#"forbid(principal, action == SecCore::Action::"file.write", resource)
        when {
            (context.input.operation == SecCore::WriteOperation::"delete" && (resource.path == "/tree" || resource.path like "/tree/*") && resource.path != "/tree/cache")
            || (context.input.operation == SecCore::WriteOperation::"write" && ["/tree/cache", "/config"].contains(resource.path))
        };
        forbid(principal, action == SecCore::Action::"file.write", resource)
        when { context.input.operation == SecCore::WriteOperation::"write" && (resource.path == "/other" || resource.path like "/other/*") }
        unless { resource.path == "/other/cache" || resource.path like "/other/cache/*" };
        forbid(principal, action == SecCore::Action::"file.read", resource)
        when { ["/config", "/tree/cache"].contains(resource.path) || resource.path == "/secret" }
        unless { resource.path == "/tree/cache" };"#;
    let lowered = translate(source);
    // Baseline permit isolates forbid matching from Cedar's default-deny rule.
    let policies: cedar_policy::PolicySet = format!("permit(principal, action, resource);{source}")
        .parse()
        .unwrap();
    let authorizer = cedar_policy::Authorizer::new();
    for path in [
        "/tree",
        "/tree/new",
        "/tree/cache",
        "/treehouse",
        "/config",
        "/secret",
        "/other",
        "/other/cache",
        "/other/cache/new",
        "/other/new",
        "/outside",
    ] {
        let entities = cedar_policy::Entities::from_json_value(
            json!([{
                "uid":{"type":"SecCore::File","id":"request"}, "attrs":{"path":path},"parents":[]
            }]),
            None,
        )
        .unwrap();
        for operation in ["read", "delete", "write", "create", "rename", "setattr"] {
            let input = if operation == "read" {
                json!({"program":"/bin/test"})
            } else {
                json!({"program":"/bin/test", "operation":{"__entity":{"type":"SecCore::WriteOperation","id":operation}}})
            };
            let context =
                cedar_policy::Context::from_json_value(json!({"input":input}), None).unwrap();
            let action = if operation == "read" {
                "file.read"
            } else {
                "file.write"
            };
            let request = cedar_policy::Request::new(
                "SecCore::Subject::\"test\"".parse().unwrap(),
                format!("SecCore::Action::\"{action}\"").parse().unwrap(),
                "SecCore::File::\"request\"".parse().unwrap(),
                context,
                None,
            )
            .unwrap();
            let denied = authorizer
                .is_authorized(&request, &policies, &entities)
                .decision()
                == cedar_policy::Decision::Deny;
            let blocked = lowered["targets"].as_array().unwrap().iter().any(|target| {
                let active = match operation {
                    "read" => target["protections"]["read"].as_bool().unwrap_or(false),
                    "delete" => target["protections"]["delete"].as_bool().unwrap(),
                    "write" => target["protections"]["ordinary_write"].as_bool().unwrap(),
                    _ => false,
                };
                let matches = |root: &str, tree: bool| {
                    path == root || tree && path.starts_with(&format!("{root}/"))
                };
                active
                    && matches(
                        target["path"].as_str().unwrap(),
                        target["kind"] == "directory_tree",
                    )
                    && !target["exclusions"].as_array().unwrap().iter().any(|ex| {
                        matches(
                            ex["path"].as_str().unwrap(),
                            ex["kind"] == "directory_subtree",
                        )
                    })
            });
            assert_eq!(blocked, denied, "{operation} {path}");
        }
    }
}
