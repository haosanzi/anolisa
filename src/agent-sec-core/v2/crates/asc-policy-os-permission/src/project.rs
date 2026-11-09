//! Walks the public Cedar syntax tree and keeps only what bind mounts can express.

use std::collections::BTreeSet;
use std::str::FromStr;

use asc_os_permission_types::{
    ExecutionPermissions, FileRight, FilesystemDefault, FilesystemPermissions, FilesystemRule,
    NetworkMode, NetworkPermissions, OsPermissionSet, RuleEffect, Validate,
};
use cedar_policy::{ActionConstraint, Effect, Policy, PolicySet};
use cedar_policy_core::ast::{
    BinaryOp, Expr, ExprKind, Literal, Pattern, PatternElem, UnaryOp, Var,
};
use thiserror::Error;

use crate::{ProjectionReport, SandboxProfile};

/// Maximum statements one projection accepts.
pub const MAX_POLICIES: usize = 1024;

const ALL_ACTIONS: [&str; 5] = [
    "file.read",
    "file.write",
    "file.exec",
    "process.spawn",
    "network.use",
];

/// Projection failures; none of them produces a partial permission set.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProjectError {
    /// The text is not a static Cedar policy set.
    #[error("sandbox projection requires parsable static Cedar policies")]
    Syntax,
    /// Linked templates cannot be projected without their values.
    #[error("sandbox projection does not support linked templates")]
    Template,
    /// The statement count exceeds the projection budget.
    #[error("sandbox projection supports at most {MAX_POLICIES} policies")]
    TooMany,
    /// The projected permissions violate the OS permission contract.
    #[error("projected OS permissions are invalid: {0}")]
    Invalid(String),
}

pub(super) fn project(text: &str) -> Result<SandboxProfile, ProjectError> {
    let policies = PolicySet::from_str(text).map_err(|_| ProjectError::Syntax)?;
    if policies.templates().next().is_some() {
        return Err(ProjectError::Template);
    }
    let mut read = BTreeSet::new();
    let mut explicit_read = BTreeSet::new();
    let mut write = BTreeSet::new();
    let mut noexec = BTreeSet::new();
    let mut unprojected = Vec::new();
    let mut network = false;
    let mut launch_permitted = false;
    let mut statements = 0_usize;
    for policy in policies.policies() {
        statements += 1;
        if statements > MAX_POLICIES {
            return Err(ProjectError::TooMany);
        }
        let effect = policy.effect();
        let actions = actions(policy);
        let covers = |action: &str| actions.iter().any(|name| name == action);
        if covers("network.use") {
            // Whole-network permission only: endpoint and principal conditions stay with the PDP.
            network |= effect == Effect::Permit;
        }
        if effect == Effect::Permit && (covers("process.spawn") || covers("file.exec")) {
            launch_permitted = true;
        }
        if !(covers("file.read") || covers("file.write") || covers("file.exec")) {
            continue;
        }
        match literal_paths(policy) {
            Ok(paths) => {
                if effect == Effect::Permit {
                    if covers("file.read") {
                        explicit_read.extend(paths.iter().cloned());
                        read.extend(paths.iter().cloned());
                    }
                    if covers("file.write") {
                        // A writable bind mount also exposes the existing contents.
                        read.extend(paths.iter().cloned());
                        write.extend(paths.iter().cloned());
                    }
                } else if covers("file.exec") {
                    noexec.extend(paths);
                } else {
                    // A filesystem forbid is enforced per request by the PDP, which can express
                    // operations and context facts that a bind mount cannot.
                    unprojected.push(format!(
                        "{}: {} is enforced by the PDP, not by the mount table",
                        policy.id(),
                        if effect == Effect::Permit {
                            "permit"
                        } else {
                            "forbid"
                        }
                    ));
                }
            }
            Err(reason) => unprojected.push(format!("{}: {reason}", policy.id())),
        }
    }
    let permissions = permissions(&read, &write, &noexec, network)?;
    let report = ProjectionReport {
        read_paths: read.into_iter().collect(),
        write_paths: write.iter().cloned().collect(),
        noexec_paths: noexec.into_iter().collect(),
        network: permissions.network.mode,
        launch_permitted,
        unprojected,
        warnings: uncovered_writes(&explicit_read, &write),
    };
    Ok(SandboxProfile {
        permissions,
        report,
    })
}

/// Reports writable paths no `file.read` permit covers.
///
/// The PDP intersects read and write, so an uncovered write silently degrades to read-only at
/// launch. The projection keeps the rule (the policy may still be extended) but the operator has
/// to see the mismatch before approving the policy.
fn uncovered_writes(explicit_read: &BTreeSet<String>, write: &BTreeSet<String>) -> Vec<String> {
    write
        .iter()
        .filter(|path| !explicit_read.iter().any(|root| covers(root, path)))
        .map(|path| {
            format!("write path {path} has no file.read permit; the PDP denies writes without read")
        })
        .collect()
}

fn covers(parent: &str, child: &str) -> bool {
    child == parent
        || child
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn permissions(
    read: &BTreeSet<String>,
    write: &BTreeSet<String>,
    noexec: &BTreeSet<String>,
    network: bool,
) -> Result<OsPermissionSet, ProjectError> {
    let mut rules = Vec::new();
    for path in read.iter().filter(|path| !write.contains(*path)) {
        rules.push(FilesystemRule {
            effect: RuleEffect::Allow,
            path: path.clone(),
            rights: vec![FileRight::Read],
        });
    }
    for path in write {
        rules.push(FilesystemRule {
            effect: RuleEffect::Allow,
            path: path.clone(),
            rights: vec![FileRight::Read, FileRight::Write],
        });
    }
    let permissions = OsPermissionSet {
        version: 1,
        filesystem: FilesystemPermissions {
            default: FilesystemDefault::Deny,
            rules,
        },
        execution: ExecutionPermissions {
            deny_paths: noexec.iter().cloned().collect(),
        },
        network: NetworkPermissions {
            mode: if network {
                NetworkMode::Full
            } else {
                NetworkMode::Off
            },
        },
    };
    permissions
        .validate()
        .map_err(|error| ProjectError::Invalid(error.to_string()))?;
    Ok(permissions)
}

fn actions(policy: &Policy) -> Vec<String> {
    match policy.action_constraint() {
        ActionConstraint::Any => ALL_ACTIONS.iter().map(|name| (*name).to_owned()).collect(),
        ActionConstraint::Eq(action) => vec![action_name(&action)],
        ActionConstraint::In(actions) => actions.iter().map(action_name).collect(),
    }
}

fn action_name(action: &cedar_policy::EntityUid) -> String {
    let name: &str = action.id().as_ref();
    name.to_owned()
}

/// Collects the literal paths one statement guarantees, or the reason it cannot be projected.
///
/// Only positive path predicates describe a mount. A negated predicate (`!=`, `not like`) can
/// only remove access from a grant, so it is dropped here and left to the PDP, which sees the
/// whole policy and applies the narrowing per request. A positive predicate the mount table
/// cannot express is still refused rather than approximated.
fn literal_paths(policy: &Policy) -> Result<BTreeSet<String>, String> {
    let ast: &cedar_policy_core::ast::Policy = policy.as_ref();
    let mut paths = BTreeSet::new();
    if let Some(condition) = ast.non_scope_constraints() {
        walk(condition, &mut paths, true).map_err(str::to_owned)?;
    }
    Ok(paths)
}

fn walk(
    expression: &Expr,
    paths: &mut BTreeSet<String>,
    positive: bool,
) -> Result<(), &'static str> {
    match expression.expr_kind() {
        ExprKind::BinaryApp {
            op: BinaryOp::Eq,
            arg1,
            arg2,
        } => {
            if positive
                && let Some(path) = path_equality(arg1, arg2).or_else(|| path_equality(arg2, arg1))
            {
                paths.insert(path.to_owned());
                return Ok(());
            }
            // Any other equality joins two independent predicates.
            walk(arg1, paths, positive)?;
            walk(arg2, paths, positive)?;
            return Ok(());
        }
        // Negation flips the polarity so a narrowing predicate never becomes a mount.
        ExprKind::UnaryApp {
            op: UnaryOp::Not,
            arg,
        } => return walk(arg, paths, !positive),
        ExprKind::Like {
            expr: target,
            pattern,
        } if is_resource_path(target) => {
            if positive {
                paths.insert(pattern_path(pattern)?);
            }
            return Ok(());
        }
        ExprKind::Is { expr: target, .. } | ExprKind::HasAttr { expr: target, .. }
            if is_resource(target) =>
        {
            return Ok(());
        }
        // Runtime facts filter one request; they cannot describe a mount.
        ExprKind::Var(Var::Context) => return Ok(()),
        ExprKind::Var(Var::Resource) => {
            return Err("resource outside a path predicate is not projected");
        }
        ExprKind::And { left, right } | ExprKind::Or { left, right } => {
            walk(left, paths, positive)?;
            walk(right, paths, positive)?;
            return Ok(());
        }
        _ => {}
    }
    // A positive predicate that reshapes a path is refused rather than approximated; the same
    // predicate under negation only narrows, which the PDP already enforces.
    if positive && mentions_resource_path(expression) {
        return Err("path expression is not a positive literal or directory prefix");
    }
    Ok(())
}

fn path_equality<'a>(expression: &Expr, literal: &'a Expr) -> Option<&'a str> {
    if !is_resource_path(expression) {
        return None;
    }
    match literal.expr_kind() {
        ExprKind::Lit(Literal::String(value)) => Some(value.as_str()),
        _ => None,
    }
}

fn is_resource(expression: &Expr) -> bool {
    matches!(expression.expr_kind(), ExprKind::Var(Var::Resource))
}

fn is_resource_path(expression: &Expr) -> bool {
    matches!(expression.expr_kind(), ExprKind::GetAttr { expr, attr }
        if attr == "path" && is_resource(expr))
}

/// Reports whether a subtree still reads `resource.path`, i.e. a predicate still to be projected.
fn mentions_resource_path(expression: &Expr) -> bool {
    if is_resource_path(expression) {
        return true;
    }
    match expression.expr_kind() {
        ExprKind::Var(Var::Resource) => true,
        ExprKind::And { left, right } | ExprKind::Or { left, right } => {
            mentions_resource_path(left) || mentions_resource_path(right)
        }
        ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        } => {
            mentions_resource_path(test_expr)
                || mentions_resource_path(then_expr)
                || mentions_resource_path(else_expr)
        }
        ExprKind::UnaryApp { arg, .. } => mentions_resource_path(arg),
        ExprKind::BinaryApp { arg1, arg2, .. } => {
            mentions_resource_path(arg1) || mentions_resource_path(arg2)
        }
        ExprKind::ExtensionFunctionApp { args, .. } | ExprKind::Set(args) => {
            args.iter().any(mentions_resource_path)
        }
        ExprKind::GetAttr { expr, .. }
        | ExprKind::HasAttr { expr, .. }
        | ExprKind::ExtHasAttr { expr, .. }
        | ExprKind::Like { expr, .. }
        | ExprKind::Is { expr, .. } => mentions_resource_path(expr),
        ExprKind::Record(fields) => fields.values().any(mentions_resource_path),
        _ => false,
    }
}

/// Converts an exact or trailing-`/*` pattern into the directory it covers.
fn pattern_path(pattern: &Pattern) -> Result<String, &'static str> {
    let mut value = String::new();
    let elements = pattern.get_elems();
    for (index, element) in elements.iter().enumerate() {
        match element {
            PatternElem::Char(character) => value.push(*character),
            PatternElem::Wildcard if index + 1 == elements.len() && value.ends_with('/') => {
                if value.len() > 1 {
                    value.pop();
                }
                return Ok(value);
            }
            PatternElem::Wildcard => {
                return Err("only a trailing directory wildcard becomes a mount");
            }
        }
    }
    Ok(value)
}
