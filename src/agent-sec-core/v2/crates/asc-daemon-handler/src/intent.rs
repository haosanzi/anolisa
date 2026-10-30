//! Intent wire decoding, budgets and error mapping; the core owns model calls, binding and compilation.

use asc_daemon_core::PeerCredentials;
use asc_daemon_core::intent::{IntentInput, IntentService, IntentServiceError};
use asc_daemon_protocol::intent::{
    INTENT_MATERIAL_BYTES, INTENT_OBJECTS, INTENT_REQUEST_BYTES, INTENT_TASK_BYTES,
    IntentMaterialVersion, IntentProposeParams, IntentProposeResult, IntentScopeKind,
};
use asc_daemon_protocol::{DaemonRequest, DaemonResponse, RequestId, error_code};
use asc_daemon_service::DispatchControl;
use asc_intent::{Material, MaterialVersion, ResourceScope, ScopeKind};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

pub(crate) fn handle(
    request_id: RequestId,
    peer: PeerCredentials,
    control: &DispatchControl,
    service: Option<&IntentService>,
    request: DaemonRequest,
) -> DaemonResponse {
    let result = (|| {
        let encoded =
            serde_json::to_vec(&request).map_err(|_| IntentServiceError::InvalidArgument)?;
        if encoded.len() >= INTENT_REQUEST_BYTES {
            return Err(IntentServiceError::ResourceExhausted);
        }
        let params: IntentProposeParams = serde_json::from_value(request.params)
            .map_err(|_| IntentServiceError::InvalidArgument)?;
        let input = decode(params)?;
        let service = service.ok_or(IntentServiceError::Unavailable)?;
        let outcome =
            service.propose(peer, request_id.as_str(), input, control.deadline(), || {
                control.is_cancelled()
            })?;
        let value = serde_json::to_value(outcome).map_err(|_| IntentServiceError::Internal)?;
        let response: IntentProposeResult =
            serde_json::from_value(value).map_err(|_| IntentServiceError::Internal)?;
        serde_json::to_value(response).map_err(|_| IntentServiceError::Internal)
    })();
    match result {
        Ok(result) => DaemonResponse::success(request_id, result),
        Err(error) => {
            let code = match error {
                IntentServiceError::InvalidArgument => error_code::INVALID_ARGUMENT,
                IntentServiceError::ResourceExhausted => error_code::RESOURCE_EXHAUSTED,
                IntentServiceError::Unavailable => error_code::UNAVAILABLE,
                IntentServiceError::DeadlineExceeded => error_code::DEADLINE_EXCEEDED,
                IntentServiceError::Internal => error_code::INTERNAL,
            };
            DaemonResponse::error(request_id, code, &error.to_string())
        }
    }
}

fn decode(params: IntentProposeParams) -> Result<IntentInput, IntentServiceError> {
    if params.task.len() > INTENT_TASK_BYTES
        || params.scopes.len() > INTENT_OBJECTS
        || params.materials.len() > INTENT_OBJECTS
    {
        return Err(IntentServiceError::ResourceExhausted);
    }
    let mut total = 0;
    let mut materials = Vec::with_capacity(params.materials.len());
    for material in params.materials {
        let content = STANDARD
            .decode(&material.content_base64)
            .map_err(|_| IntentServiceError::InvalidArgument)?;
        if STANDARD.encode(&content) != material.content_base64 {
            return Err(IntentServiceError::InvalidArgument);
        }
        total += content.len();
        if total > INTENT_MATERIAL_BYTES {
            return Err(IntentServiceError::ResourceExhausted);
        }
        materials.push(Material {
            scope: material.scope,
            path: material.path,
            version: match material.version {
                IntentMaterialVersion::Before => MaterialVersion::Before,
                IntentMaterialVersion::Current => MaterialVersion::Current,
            },
            content,
        });
    }
    Ok(IntentInput {
        task: params.task,
        working_directory: params.working_directory,
        ttl: params.ttl,
        scopes: params
            .scopes
            .into_iter()
            .map(|scope| ResourceScope {
                name: scope.name,
                kind: match scope.kind {
                    IntentScopeKind::Changes => ScopeKind::Changes,
                    IntentScopeKind::Directory => ScopeKind::Directory,
                    IntentScopeKind::Attachment => ScopeKind::Attachment,
                },
                base: scope.base,
            })
            .collect(),
        materials,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decoded_material_and_task_budgets_reject_the_whole_request() {
        let valid = json!({"task":"read a","ttl":1,"scopes":[],"materials":[
            {"scope":"a","path":"a","version":"current","content_base64":STANDARD.encode(vec![0; INTENT_MATERIAL_BYTES])}
        ]});
        assert!(decode(serde_json::from_value(valid.clone()).unwrap()).is_ok());
        let mut too_large = valid.clone();
        too_large["materials"]
            .as_array_mut()
            .unwrap()
            .push(json!({"scope":"a","path":"b","version":"current","content_base64":"YQ=="}));
        assert!(matches!(
            decode(serde_json::from_value(too_large).unwrap()),
            Err(IntentServiceError::ResourceExhausted)
        ));
        let mut too_many = valid;
        too_many["materials"] = json!(vec![
            json!({"scope":"a","path":"a","version":"current","content_base64":""});
            INTENT_OBJECTS + 1
        ]);
        assert!(matches!(
            decode(serde_json::from_value(too_many).unwrap()),
            Err(IntentServiceError::ResourceExhausted)
        ));
        let oversized_task =
            json!({"task":"x".repeat(INTENT_TASK_BYTES + 1),"ttl":1,"scopes":[],"materials":[]});
        assert!(matches!(
            decode(serde_json::from_value(oversized_task).unwrap()),
            Err(IntentServiceError::ResourceExhausted)
        ));
    }

    #[test]
    fn cwd_is_passed_through_and_never_filled_from_daemon_environment() {
        for cwd in [None, Some("/caller/工作区")] {
            let mut value =
                json!({"task":"当前目录下有几个文件", "ttl":30, "scopes":[], "materials":[]});
            if let Some(cwd) = cwd {
                value["working_directory"] = json!(cwd);
            }
            let decoded = decode(serde_json::from_value(value).unwrap()).unwrap();
            assert_eq!(decoded.working_directory.as_deref(), cwd);
            assert!(decoded.materials.is_empty());
        }
    }

    #[test]
    fn base64_must_be_canonical_and_padded() {
        for (text, valid) in [
            ("YQ==", true),
            ("YQ", false),
            ("YR==", false),
            ("YQ==\n", false),
            ("_w==", false),
        ] {
            let params = serde_json::from_value(json!({"task":"read a","ttl":1,"scopes":[],
                "materials":[{"scope":"a","path":"a","version":"current","content_base64":text}]}))
            .unwrap();
            assert_eq!(decode(params).is_ok(), valid);
        }
        assert_eq!(INTENT_MATERIAL_BYTES, asc_intent::MAX_MATERIAL_BYTES);
        assert_eq!(INTENT_OBJECTS, asc_intent::MAX_OBJECTS);
    }
}
