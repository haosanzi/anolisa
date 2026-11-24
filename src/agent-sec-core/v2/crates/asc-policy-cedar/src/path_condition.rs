//! Recognizes literal filesystem path conditions in Cedar syntax.

use cedar_policy::pst::{BinaryOp, Expr, Literal, PatternElem, Var};

pub(crate) fn is_resource_path(expr: &Expr) -> bool {
    matches!(expr, Expr::GetAttr { expr, attr } if attr == "path" && matches!(expr.as_ref(), Expr::Var(Var::Resource)))
}

/// Returns the literal in an equality condition on `resource.path`.
pub fn exact_path(expr: &Expr) -> Option<&str> {
    let Expr::BinaryOp {
        op: BinaryOp::Eq,
        left,
        right,
    } = expr
    else {
        return None;
    };
    match (left.as_ref(), right.as_ref()) {
        (field, Expr::Literal(Literal::String(path)))
        | (Expr::Literal(Literal::String(path)), field)
            if is_resource_path(field) =>
        {
            Some(path)
        }
        _ => None,
    }
}

/// Returns the root of a condition matching a path and all its descendants.
/// The equality for the root is required in addition to the descendant pattern.
pub fn directory_tree_root(expr: &Expr) -> Option<&str> {
    let Expr::BinaryOp {
        op: BinaryOp::Or,
        left,
        right,
    } = expr
    else {
        return None;
    };
    directory_pair(left, right).or_else(|| directory_pair(right, left))
}

fn directory_pair<'a>(root: &'a Expr, children: &Expr) -> Option<&'a str> {
    let path = exact_path(root)?;
    let Expr::Like { expr, pattern } = children else {
        return None;
    };
    let (PatternElem::Wildcard, prefix) = pattern.split_last()? else {
        return None;
    };
    let expected = path.chars().chain((path != "/").then_some('/'));
    let actual = prefix.iter().map(|part| match part {
        PatternElem::Char(ch) => Some(*ch),
        PatternElem::Wildcard => None,
    });
    (is_resource_path(expr) && actual.eq(expected.map(Some))).then_some(path)
}
