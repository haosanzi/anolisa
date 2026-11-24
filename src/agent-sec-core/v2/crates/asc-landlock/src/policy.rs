//! Compile the supported Cedar file access rules to Landlock path grants.

use std::collections::BTreeMap;

use asc_os_permission_types::path_contains;
use asc_policy_cedar::path_condition::{directory_tree_root, exact_path};
use asc_policy_types::cedar::CedarPolicySource;
use cedar_policy::pst::{
    ActionConstraint, BinaryOp, Clause, Effect, Expr, PrincipalConstraint, ResourceConstraint,
};

use crate::{LandlockError, MAX_PATHS, invalid, validate_path};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Scope {
    pub path: String,
    pub tree: bool,
}

impl Scope {
    fn new(path: &str, tree: bool) -> Result<Self, LandlockError> {
        validate_path(path)?;
        Ok(Self {
            path: path.into(),
            tree,
        })
    }

    fn contains(&self, other: &Self) -> bool {
        self == other || self.tree && path_contains(&self.path, &other.path)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Rights {
    pub read: bool,
    pub write: bool,
}

#[derive(Default)]
struct Constraints {
    permits: Vec<Scope>,
    forbids: Vec<Scope>,
    limits: Vec<Vec<Scope>>,
}

impl Constraints {
    fn apply(&mut self, effect: Effect, positive: bool, scopes: &[Scope]) {
        match (effect, positive) {
            (Effect::Permit, _) => self.permits.extend_from_slice(scopes),
            (Effect::Forbid, true) => self.forbids.extend_from_slice(scopes),
            (Effect::Forbid, false) => self.limits.push(scopes.to_vec()),
        }
    }

    fn grants(self) -> Result<Vec<Scope>, LandlockError> {
        // Intersect every permit with each global forbid's exception set. Within
        // this path grammar the intersection of two ranges is the narrower one.
        let mut grants = self.permits;
        for limit in self.limits {
            let mut next = std::collections::BTreeSet::new();
            for grant in &grants {
                for range in &limit {
                    if grant.contains(range) {
                        next.insert(range.clone());
                    } else if range.contains(grant) {
                        next.insert(grant.clone());
                    }
                    if next.len() > MAX_PATHS {
                        return Err(invalid("too many effective Landlock path grants"));
                    }
                }
            }
            grants = next.into_iter().collect();
        }

        grants.retain(|grant| !self.forbids.iter().any(|forbid| forbid.contains(grant)));
        for grant in &grants {
            if let Some(forbid) = self.forbids.iter().find(|forbid| grant.contains(forbid)) {
                return Err(invalid(format!(
                    "permission at {} would cover forbidden path {}",
                    grant.path, forbid.path
                )));
            }
        }
        Ok(grants)
    }
}

pub(super) fn compile(
    source: &CedarPolicySource,
) -> Result<BTreeMap<Scope, Rights>, LandlockError> {
    let syntax = asc_policy_cedar::pst(source)?;
    if syntax.policies.is_empty() {
        return Err(invalid("the policy is empty"));
    }
    let mut read = Constraints::default();
    let mut write = Constraints::default();
    let mut total_paths = 0;
    for (id, policy) in &syntax.policies {
        let result = (|| {
            let body = policy.body();
            if !matches!(body.principal, PrincipalConstraint::Any)
                && !matches!(&body.principal, PrincipalConstraint::Is(name) if name.to_string() == "SecCore::Subject")
            {
                return Err(invalid("unsupported principal selector"));
            }
            if !matches!(body.resource, ResourceConstraint::Any)
                && !matches!(&body.resource, ResourceConstraint::Is(name) if name.to_string() == "SecCore::File")
            {
                return Err(invalid("expected a file resource"));
            }
            if body.annotations.keys().any(|key| key.as_str() != "id") {
                return Err(invalid(
                    "annotations requiring runtime decisions are unsupported",
                ));
            }
            let actions = actions(&body.action)?;
            let (positive, scopes) = match body.clauses().as_slice() {
                [] => (true, vec![Scope::new("/", true)?]),
                [Clause::When(expr)] => (true, paths(expr)?),
                [Clause::Unless(expr)] if body.effect == Effect::Forbid => (false, paths(expr)?),
                _ => return Err(invalid("expected one static path condition")),
            };
            total_paths += scopes.len();
            if total_paths > MAX_PATHS {
                return Err(invalid("too many Landlock policy paths"));
            }
            if actions.read {
                read.apply(body.effect, positive, &scopes);
            }
            if actions.write {
                write.apply(body.effect, positive, &scopes);
            }
            Ok(())
        })();
        result.map_err(|error: LandlockError| invalid(format!("Cedar statement {id}: {error}")))?;
    }

    let mut plan: BTreeMap<Scope, Rights> = BTreeMap::new();
    for path in read.grants()? {
        plan.entry(path).or_default().read = true;
    }
    for path in write.grants()? {
        plan.entry(path).or_default().write = true;
    }
    Ok(plan)
}

fn actions(constraint: &ActionConstraint) -> Result<Rights, LandlockError> {
    let ids = match constraint {
        ActionConstraint::Eq(id) => std::slice::from_ref(id),
        ActionConstraint::In(ids) if !ids.is_empty() => ids.as_slice(),
        _ => return Err(invalid("expected explicit file.read or file.write actions")),
    };
    let mut rights = Rights::default();
    for id in ids {
        if id.ty.to_string() != "SecCore::Action" {
            return Err(invalid("expected SecCore actions"));
        }
        match id.eid.as_str() {
            "file.read" => rights.read = true,
            "file.write" => rights.write = true,
            action => return Err(invalid(format!("unsupported Landlock action: {action}"))),
        }
    }
    Ok(rights)
}

fn paths(expr: &Expr) -> Result<Vec<Scope>, LandlockError> {
    let mut pending = vec![expr];
    let mut scopes = Vec::new();
    while let Some(expr) = pending.pop() {
        if pending.len() + scopes.len() >= MAX_PATHS {
            return Err(invalid("too many paths in a Landlock condition"));
        }
        if let Some(path) = directory_tree_root(expr) {
            scopes.push(Scope::new(path, true)?);
        } else if let Some(path) = exact_path(expr) {
            scopes.push(Scope::new(path, false)?);
        } else if let Expr::BinaryOp {
            op: BinaryOp::Or,
            left,
            right,
        } = expr
        {
            pending.extend([left.as_ref(), right.as_ref()]);
        } else {
            return Err(invalid(
                "expected a literal file path or a directory with its descendants",
            ));
        }
    }
    Ok(scopes)
}
