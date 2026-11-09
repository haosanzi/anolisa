use asc_os_permission_types::{FileRight, NetworkMode, RuleEffect};
use asc_policy_os_permission::{ProjectError, project};

fn read_rule(path: &str, rights: &[FileRight]) -> String {
    format!("{path} {rights:?}")
}

#[test]
fn literal_grants_become_mount_rules_and_the_rest_is_reported() {
    let profile = project(
        r#"
permit(principal, action == SecCore::Action::"process.spawn", resource)
when { principal has agent_type && principal.agent_type == "cosh" };

permit(principal, action == SecCore::Action::"file.read", resource)
when {
    resource.path == "/usr" || resource.path like "/usr/*" ||
    resource.path == "/lib" || resource.path like "/lib/*"
};

permit(principal, action == SecCore::Action::"file.write", resource)
when {
    context.input.operation == SecCore::WriteOperation::"write" &&
    (resource.path == "/work" || resource.path like "/work/*")
};

permit(principal, action == SecCore::Action::"network.use", resource);

forbid(principal, action == SecCore::Action::"file.read", resource)
when { resource.path == "/work/secret" };

forbid(principal, action == SecCore::Action::"file.exec", resource)
when { resource.path like "/work/bin/*" };
"#,
    )
    .unwrap();

    let rules: Vec<_> = profile
        .permissions
        .filesystem
        .rules
        .iter()
        .map(|rule| read_rule(&rule.path, &rule.rights))
        .collect();
    assert_eq!(
        rules,
        [
            read_rule("/lib", &[FileRight::Read]),
            read_rule("/usr", &[FileRight::Read]),
            read_rule("/work", &[FileRight::Read, FileRight::Write]),
        ]
    );
    assert!(
        profile
            .permissions
            .filesystem
            .rules
            .iter()
            .all(|rule| rule.effect == RuleEffect::Allow)
    );
    assert_eq!(profile.report.network, NetworkMode::Full);
    assert!(profile.report.launch_permitted);
    assert_eq!(profile.report.noexec_paths, ["/work/bin"]);
    // The read forbid cannot be a mount rule, so the PDP keeps enforcing it.
    assert_eq!(profile.report.unprojected.len(), 1);
    assert!(profile.report.unprojected[0].contains("enforced by the PDP"));
    // /work is writable but no file.read permit covers it, so the PDP would deny the write.
    assert_eq!(profile.report.warnings.len(), 1);
    assert!(profile.report.warnings[0].contains("has no file.read permit"));
}

#[test]
fn narrowing_predicates_stay_with_the_pdp_and_reshaping_ones_are_refused() {
    let profile = project(
        r#"
permit(principal, action == SecCore::Action::"file.read", resource)
when { resource.path != "/etc" };

permit(principal, action == SecCore::Action::"file.read", resource)
when { resource.path like "/work/*/private" };

permit(principal, action == SecCore::Action::"file.write", resource)
when { resource.path == "/safe" };
"#,
    )
    .unwrap();
    let paths: Vec<_> = profile
        .permissions
        .filesystem
        .rules
        .iter()
        .map(|rule| rule.path.as_str())
        .collect();
    assert_eq!(paths, ["/safe"]);
    assert_eq!(profile.report.unprojected.len(), 1);
    assert!(profile.report.unprojected[0].contains("trailing directory wildcard"));
    assert_eq!(profile.report.warnings.len(), 1);
    assert!(profile.report.warnings[0].contains("/safe"));
    assert_eq!(profile.report.network, NetworkMode::Off);
    assert!(!profile.report.launch_permitted);
}

#[test]
fn positive_paths_survive_an_exclusion_in_the_same_permit() {
    // The model commonly writes one grant with an inline exclusion; the mount keeps the grant
    // and the PDP removes the excluded subtree per request.
    let profile = project(
        r#"
permit(principal, action == SecCore::Action::"file.read", resource)
when {
    (resource.path == "/data" || resource.path like "/data/*") &&
    resource.path != "/data/secret" &&
    !(resource.path like "/data/secret/*")
};

forbid(principal, action == SecCore::Action::"file.read", resource)
when { resource.path == "/data/secret" || resource.path like "/data/secret/*" };
"#,
    )
    .unwrap();
    let paths: Vec<_> = profile
        .permissions
        .filesystem
        .rules
        .iter()
        .map(|rule| rule.path.as_str())
        .collect();
    assert_eq!(paths, ["/data"]);
    assert_eq!(profile.report.unprojected.len(), 1);
    assert!(profile.report.unprojected[0].contains("enforced by the PDP"));
    assert!(profile.report.warnings.is_empty());
}

#[test]
fn unparsable_or_templated_text_is_rejected() {
    assert_eq!(project("permit("), Err(ProjectError::Syntax));
    assert_eq!(
        project("permit(principal == ?principal, action, resource);"),
        Err(ProjectError::Template)
    );
}
