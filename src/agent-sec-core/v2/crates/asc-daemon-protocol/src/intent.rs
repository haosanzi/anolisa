//! Strict wire contracts for initial intent proposals; materials and candidates grant no authority.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum bytes in a complete business request, including the newline.
pub const INTENT_REQUEST_BYTES: usize = 2 * 1024 * 1024;
/// Maximum bytes in a complete business result, which excludes file contents.
pub const INTENT_RESULT_BYTES: usize = 512 * 1024;
/// Maximum bytes of task text per request.
pub const INTENT_TASK_BYTES: usize = 64 * 1024;
/// Maximum combined bytes of decoded materials.
pub const INTENT_MATERIAL_BYTES: usize = 1024 * 1024;
/// Maximum count of objects and of scopes per snapshot.
pub const INTENT_OBJECTS: usize = 256;

/// Task, materials and relative lifetime; caller identity and trust assertions are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentProposeParams {
    /// Original task text; the only user content sent to the cloud.
    pub task: String,
    /// Normalized absolute cwd in the caller's namespace; neither model input nor authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    /// Requested lifetime in seconds, from 1 to 1800.
    pub ttl: u32,
    /// Bounded material sources within this request.
    pub scopes: Vec<IntentScope>,
    /// Material contents encoded as standard padded base64.
    pub materials: Vec<IntentMaterial>,
}

/// Source description, not permission to access a host path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentScope {
    /// Unique name within the request.
    pub name: String,
    /// Complete directory, file attachment or change set with a baseline.
    pub kind: IntentScopeKind,
    /// Baseline present only for change sets.
    pub base: Option<String>,
}

/// Closed set of supported input scopes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentScopeKind {
    /// Materials changed between HEAD and the worktree.
    Changes,
    /// Explicitly supplied complete, bounded directory.
    Directory,
    /// Explicitly supplied file.
    Attachment,
}

/// Unapproved material bytes whose digests must be recomputed by the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentMaterial {
    /// Name of the containing scope.
    pub scope: String,
    /// Normalized relative path used only as source attribution.
    pub path: String,
    /// Baseline or current version.
    pub version: IntentMaterialVersion,
    /// Standard base64 contents; caller-provided digests are not accepted.
    pub content_base64: String,
}

/// Material version; deleted objects have only a baseline version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentMaterialVersion {
    /// Baseline contents.
    Before,
    /// Currently collected contents.
    Current,
}

/// Closed initial proposal outcomes preserving the core candidate JSON.
/// Deserializing a candidate does not grant authority.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum IntentProposeResult {
    /// Candidate that is neither approved nor effective.
    Candidate {
        /// Complete `asc.intent.candidate.v1`; consumers must validate display fields.
        candidate: Value,
    },
    /// Unresolved requirements or resource issues, without a Cedar candidate.
    NeedsClarification {
        /// Original intent draft and evidence.
        draft: Value,
        /// Semantic issues from the core's closed issue vocabulary.
        intent_issues: Vec<Value>,
        /// Resource issues and alternatives from the core.
        resource_issues: Vec<Value>,
    },
    /// Explicit requirements exceed the read-only template; no reduced candidate is returned.
    Rejected {
        /// Draft preserving the explicit requirements.
        draft: Value,
        /// Closed rejection reason.
        reason: IntentRejection,
    },
}

/// Initial proposals reject explicit requirements unsupported by the template.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentRejection {
    /// Request cannot be satisfied by the read-only template.
    UnsupportedRequest,
    /// The selected backend cannot enforce exact permissions; widening access is forbidden.
    UnsupportedBackend,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_authority_fields_at_every_level() {
        let valid = json!({"task":"read a", "ttl":1800,
            "scopes":[{"name":"input","kind":"attachment","base":null}],
            "materials":[{"scope":"input","path":"a","version":"current","content_base64":"YQ=="}]});
        assert!(serde_json::from_value::<IntentProposeParams>(valid.clone()).is_ok());
        for pointer in ["", "/scopes/0", "/materials/0"] {
            for key in [
                "trusted",
                "uid",
                "entity_id",
                "digest",
                "expires_at",
                "endpoint",
                "key",
                "filesystem_capabilities",
                "required_permissions",
            ] {
                let mut bad = valid.clone();
                bad.pointer_mut(pointer)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert(key.into(), json!(true));
                assert!(serde_json::from_value::<IntentProposeParams>(bad).is_err());
            }
        }
    }

    #[test]
    fn request_budget_counts_whitespace_escaping_context_and_line_ending() {
        use crate::request_fits_budget;
        let mut wire =
            br#"{"method":"intent.propose","params":{},"traceContext":{"version":1}}"#.to_vec();
        wire.resize(INTENT_REQUEST_BYTES - 1, b' ');
        assert!(request_fits_budget(&wire).unwrap());
        wire.push(b'\n');
        assert!(request_fits_budget(&wire).unwrap());
        wire.insert(0, b' ');
        assert!(!request_fits_budget(&wire).unwrap());
        let escaped = format!(
            r#"{{"method":"intent.propose","params":{{"task":"{}"}}}}"#,
            "\\u0001".repeat(INTENT_REQUEST_BYTES / 6)
        );
        assert!(!request_fits_budget(escaped.as_bytes()).unwrap());
        let mut other = br#"{"method":"health","params":{}}"#.to_vec();
        other.resize(INTENT_REQUEST_BYTES + 1, b' ');
        assert!(request_fits_budget(&other).unwrap());
    }

    #[test]
    fn outcomes_cannot_mix_candidates_and_rejections() {
        assert!(
            serde_json::from_value::<IntentProposeResult>(json!({
                "outcome":"rejected", "draft":{}, "reason":"unsupported_request", "candidate":{}
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<IntentProposeResult>(
                json!({"outcome":"approved","candidate":{}})
            )
            .is_err()
        );
    }
}
