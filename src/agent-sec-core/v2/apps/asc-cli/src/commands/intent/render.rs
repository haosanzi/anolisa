//! Read-only views preserving daemon candidates; local hash checks neither compile nor approve policies.

use asc_daemon_protocol::intent::{INTENT_RESULT_BYTES, IntentProposeResult};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::io::{self, Write as _};

use super::{Format, IntentFailure, input::Collected};

pub(super) fn validate(
    value: &Value,
    task: &str,
    ttl: u32,
    collected: &Collected,
) -> Result<(), IntentFailure> {
    let bad = || IntentFailure::Response;
    if serde_json::to_vec(value).map_err(|_| bad())?.len() > INTENT_RESULT_BYTES {
        return Err(bad());
    }
    if value["format_version"] != "asc.intent.candidate.v1"
        || value["kind"] != "initial"
        || value["status"] != "CANDIDATE"
        || value["authorization_required"] != true
        || !matches!(
            value["profile"].as_str(),
            Some("readonly@1" | "directory-inspection@1")
        )
        || value["filesystem_contract"] != "filesystem-access@1"
        || value["contract_revision"] != 1
        || value["binding_revision"] != 1
        || value.pointer("/draft/source/sha256") != Some(&json!(digest(task.as_bytes())))
    {
        return Err(bad());
    }
    let mut content = value.clone();
    content
        .as_object_mut()
        .ok_or_else(bad)?
        .remove("candidate_hash");
    if hash(&content)? != string(value, "candidate_hash")? {
        return Err(bad());
    }
    let created_at = value["created_at"].as_i64().ok_or_else(bad)?;
    let expires_at = expiry(value)?;
    if created_at <= 0 || created_at.checked_add(i64::from(ttl)) != Some(expires_at) {
        return Err(bad());
    }
    string(value, "policy_set")?;
    let summary = value["back_translation"].as_array().ok_or_else(bad)?;
    if summary.is_empty() || summary.iter().any(|line| !line.is_string()) {
        return Err(bad());
    }
    let snapshot = &value["binding_snapshot"];
    let task_id = string(value, "task_id")?;
    if snapshot["task_id"] != task_id
        || snapshot["source"] != "request_snapshot"
        || snapshot["working_directory"] != collected.working_directory
    {
        return Err(bad());
    }
    let scopes: serde_json::Map<_, _> = collected
        .scopes
        .iter()
        .map(|scope| {
            serde_json::to_value(scope)
                .map(|value| (scope.name.clone(), value))
                .map_err(|_| bad())
        })
        .collect::<Result<_, _>>()?;
    if snapshot["scopes"] != Value::Object(scopes) {
        return Err(bad());
    }
    let mut objects = Vec::new();
    for material in &collected.materials {
        let bytes = STANDARD
            .decode(&material.content_base64)
            .map_err(|_| bad())?;
        let sha = digest(&bytes);
        let id = hash(&json!([
            task_id,
            material.scope,
            material.path,
            material.version,
            sha
        ]))?
        .replace("sha256:", "file-");
        objects.push(
            json!({"entity_id":id,"scope":material.scope,"path":material.path,
            "version":material.version,"content_sha256":sha,"byte_length":bytes.len()}),
        );
    }
    objects.sort_by(|a, b| a["entity_id"].as_str().cmp(&b["entity_id"].as_str()));
    if snapshot["objects"] != json!(objects) {
        return Err(bad());
    }
    let binding = hash(&json!([
        task_id,
        "request_snapshot",
        snapshot["scopes"],
        objects,
        collected.working_directory
    ]))?;
    if snapshot["digest"] != binding || value["binding_snapshot_digest"] != binding {
        return Err(bad());
    }
    validate_permissions(value, &objects, &collected.working_directory)
}

fn validate_permissions(value: &Value, objects: &[Value], cwd: &str) -> Result<(), IntentFailure> {
    let bad = || IntentFailure::Response;
    let reads = value["reads"].as_array().ok_or_else(bad)?;
    if reads.iter().any(|read| !objects.contains(&read["object"])) {
        return Err(bad());
    }
    let directories = value["directories"].as_array().ok_or_else(bad)?;
    validate_directories(value, cwd)?;
    let task_id = string(value, "task_id")?;
    let mut required = std::collections::BTreeSet::new();
    if !reads.is_empty() {
        required.insert("filesystem.read");
    }
    for directory in directories {
        let path = string(directory, "path")?;
        let id = hash(&json!([task_id, "directory", path]))?.replace("sha256:", "directory-");
        let permissions = directory["permissions"].as_array().ok_or_else(bad)?;
        if directory["entity_id"] != id || !reads.is_empty() || permissions.is_empty() {
            return Err(bad());
        }
        for permission in permissions {
            let action = permission.as_str().ok_or_else(bad)?;
            if !matches!(action, "filesystem.list" | "filesystem.metadata") {
                return Err(bad());
            }
            required.insert(action);
        }
    }
    if value["required_permissions"] != json!(required) {
        return Err(bad());
    }
    Ok(())
}

fn validate_directories(candidate: &Value, cwd: &str) -> Result<(), IntentFailure> {
    use std::collections::{BTreeMap, BTreeSet};
    let bad = || IntentFailure::Response;
    let intent = &candidate["draft"]["intent"];
    let actions = intent["requested_actions"].as_array().ok_or_else(bad)?;
    let permissions: BTreeSet<_> = actions
        .iter()
        .filter_map(|action| match action.as_str() {
            Some("directory_listing") => Some("filesystem.list"),
            Some("metadata") => Some("filesystem.metadata"),
            _ => None,
        })
        .collect();
    if permissions.is_empty() {
        return if candidate["directories"] == json!([]) && candidate["profile"] == "readonly@1" {
            Ok(())
        } else {
            Err(bad())
        };
    }
    if actions
        .iter()
        .any(|a| !matches!(a.as_str(), Some("directory_listing" | "metadata")))
        || candidate["profile"] != "directory-inspection@1"
        || !candidate["forbidden_actions"]
            .as_array()
            .ok_or_else(bad)?
            .contains(&json!("filesystem.read"))
    {
        return Err(bad());
    }
    let resources = intent["resources"]["read"].as_array().ok_or_else(bad)?;
    let selectors = intent["read_selectors"].as_array().ok_or_else(bad)?;
    if resources.is_empty() || resources.len() != selectors.len() {
        return Err(bad());
    }
    let mut expected: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for (resource, selector) in resources.iter().zip(selectors) {
        let path = match selector["kind"].as_str() {
            Some("current_directory") => cwd.to_owned(),
            Some("directory") => {
                let name = string(selector, "name")?;
                if name.starts_with('/') {
                    name.to_owned()
                } else if name == "." {
                    cwd.to_owned()
                } else {
                    format!(
                        "{}/{}",
                        cwd.trim_end_matches('/'),
                        name.strip_prefix("./").unwrap_or(name)
                    )
                }
            }
            _ => return Err(bad()),
        };
        if path.len() > 4096
            || !path.starts_with('/')
            || path.contains('\\')
            || path.chars().any(char::is_control)
            || (path != "/"
                && path[1..]
                    .split('/')
                    .any(|p| p.is_empty() || p == "." || p == ".."))
        {
            return Err(bad());
        }
        expected
            .entry(path)
            .or_default()
            .insert(resource.as_str().ok_or_else(bad)?);
    }
    let directories = candidate["directories"].as_array().ok_or_else(bad)?;
    if directories.len() != expected.len() {
        return Err(bad());
    }
    for (directory, (path, references)) in directories.iter().zip(expected) {
        if directory["path"] != path
            || directory["requested_as"] != json!(references)
            || directory["permissions"] != json!(permissions)
        {
            return Err(bad());
        }
    }
    Ok(())
}

pub(super) fn expiry(candidate: &Value) -> Result<i64, IntentFailure> {
    candidate["expires_at"]
        .as_i64()
        .ok_or(IntentFailure::Response)
}

pub(super) fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, IntentFailure> {
    value[key].as_str().ok_or(IntentFailure::Response)
}

pub(super) fn render(
    result: &IntentProposeResult,
    task: &str,
    format: Format,
) -> Result<u8, IntentFailure> {
    let mut out = io::stdout().lock();
    let code = match result {
        IntentProposeResult::Candidate { .. } => 0,
        IntentProposeResult::NeedsClarification { .. } => 2,
        IntentProposeResult::Rejected { .. } => 3,
    };
    match (format, result) {
        (Format::Json, _) => {
            serde_json::to_writer(&mut out, result).map_err(|_| IntentFailure::Output)?;
            writeln!(out)?;
        }
        (Format::Cedar, IntentProposeResult::Candidate { candidate }) => {
            writeln!(
                out,
                "// CANDIDATE: pending approval; not effective.\n{}",
                string(candidate, "policy_set")?
            )?;
        }
        (Format::Cedar, _) => {
            writeln!(
                io::stderr(),
                "{}",
                escape(&serde_json::to_string(result).map_err(|_| IntentFailure::Response)?)
            )?;
        }
        (Format::Text, IntentProposeResult::Candidate { candidate }) => {
            render_candidate(&mut out, candidate, task)?;
        }
        (
            Format::Text,
            IntentProposeResult::NeedsClarification {
                draft,
                intent_issues,
                resource_issues,
            },
        ) => {
            writeln!(out, "Clarification required; no candidate generated.")?;
            understanding(&mut out, draft, task)?;
            for issue in intent_issues {
                writeln!(
                    out,
                    "  Clarification: {}",
                    escape(issue_label(issue.as_str().ok_or(IntentFailure::Response)?))
                )?;
            }
            for issue in resource_issues {
                writeln!(
                    out,
                    "  Resource \"{}\": {}",
                    escape(string(issue, "requested_as")?),
                    escape(issue_label(string(issue, "reason")?))
                )?;
                if let Some(alternatives) = issue["alternatives"].as_array() {
                    for alternative in alternatives {
                        writeln!(
                            out,
                            "    Alternative: {}",
                            escape(alternative.as_str().ok_or(IntentFailure::Response)?)
                        )?;
                    }
                }
            }
        }
        (Format::Text, IntentProposeResult::Rejected { draft, reason }) => {
            writeln!(
                out,
                "No candidate generated: {}",
                match reason {
                    asc_daemon_protocol::intent::IntentRejection::UnsupportedRequest =>
                        "the current template cannot satisfy every requested action; no partial candidate is generated.",
                    asc_daemon_protocol::intent::IntentRejection::UnsupportedBackend =>
                        "the selected backend cannot enforce the exact permissions; file-content access is never substituted.",
                }
            )?;
            understanding(&mut out, draft, task)?;
        }
    }
    out.flush()?;
    Ok(code)
}

fn render_candidate(
    out: &mut impl io::Write,
    candidate: &Value,
    task: &str,
) -> Result<(), IntentFailure> {
    writeln!(out, "Candidate generated; not approved or effective.")?;
    understanding(out, &candidate["draft"], task)?;
    if let Some(cwd) = candidate["binding_snapshot"]["working_directory"].as_str() {
        writeln!(out, "\nCaller working directory\n  {}", escape(cwd))?;
    }
    directory_scope(out, candidate)?;
    content_scope(out, candidate)?;
    for scope in candidate["binding_snapshot"]["scopes"]
        .as_object()
        .ok_or(IntentFailure::Response)?
        .values()
    {
        if scope["kind"] == "changes" {
            writeln!(
                out,
                "\nChanges\n  /{}; HEAD {}; tracked HEAD-to-worktree net changes only; untracked/ignored files excluded.",
                escape(string(scope, "name")?),
                escape(string(scope, "base")?)
            )?;
        }
    }
    let until = expiry(candidate)?;
    let date = DateTime::<Utc>::from_timestamp(until, 0).ok_or(IntentFailure::Response)?;
    writeln!(
        out,
        "\nExpires\n  {} ({} seconds remaining)",
        date.to_rfc3339(),
        until.saturating_sub(Utc::now().timestamp()).max(0)
    )?;
    writeln!(
        out,
        "\nNotes\n  This is the requested scope, not existing permissions; expiry does not refresh automatically."
    )?;
    if candidate["directories"]
        .as_array()
        .is_some_and(Vec::is_empty)
    {
        writeln!(
            out,
            "  Content reads cover only received material snapshots, not the entire repository or future files."
        )?;
    } else {
        writeln!(
            out,
            "  Directory bindings are not content snapshots or OS identities; enforcement must verify the caller namespace and direct parent-child relationships."
        )?;
        writeln!(
            out,
            "  Backends must support these exact permissions; unsupported operations are rejected, never widened to content reads."
        )?;
    }
    writeln!(
        out,
        "  Trusted approval, publication and enforcement are not connected; Cedar does not guarantee task results.\n"
    )?;
    Ok(())
}

fn directory_scope(out: &mut impl io::Write, candidate: &Value) -> Result<(), IntentFailure> {
    for directory in candidate["directories"]
        .as_array()
        .ok_or(IntentFailure::Response)?
    {
        writeln!(
            out,
            "\nDirectory bindings\n  Directory: {}",
            escape(string(directory, "path")?)
        )?;
        for permission in directory["permissions"]
            .as_array()
            .ok_or(IntentFailure::Response)?
        {
            writeln!(
                out,
                "  Requested: {}",
                escape(label(permission.as_str().ok_or(IntentFailure::Response)?))
            )?;
        }
        writeln!(
            out,
            "  Direct entries only, including hidden entries; no recursion, symlink traversal or file-content reads."
        )?;
    }
    Ok(())
}

fn content_scope(out: &mut impl io::Write, candidate: &Value) -> Result<(), IntentFailure> {
    writeln!(out, "\nAllowed")?;
    let reads = candidate["reads"]
        .as_array()
        .ok_or(IntentFailure::Response)?;
    if reads.is_empty() {
        writeln!(out, "  File-content reads: none")?;
    }
    for read in reads {
        let object = &read["object"];
        writeln!(
            out,
            "  read  {} ({}, {} bytes)",
            escape(string(object, "path")?),
            escape(string(object, "version")?),
            object["byte_length"]
                .as_u64()
                .ok_or(IntentFailure::Response)?
        )?;
    }
    writeln!(out, "\nDenied")?;
    let actions = candidate["forbidden_actions"]
        .as_array()
        .ok_or(IntentFailure::Response)?
        .iter()
        .map(|action| action.as_str().ok_or(IntentFailure::Response))
        .collect::<Result<Vec<_>, _>>()?;
    for kind in ["read", "write", "execute", "network", "tools", "other"] {
        let denied: Vec<_> = actions
            .iter()
            .copied()
            .filter(|action| category(action) == kind)
            .collect();
        if !denied.is_empty() {
            writeln!(out, "  {kind:<7} {}", escape(&denied.join(", ")))?;
        }
    }
    Ok(())
}

fn draft_of(result: &IntentProposeResult) -> &Value {
    match result {
        IntentProposeResult::Candidate { candidate } => &candidate["draft"],
        IntentProposeResult::NeedsClarification { draft, .. }
        | IntentProposeResult::Rejected { draft, .. } => draft,
    }
}

pub(super) fn validate_evidence(
    result: &IntentProposeResult,
    task: &str,
) -> Result<(), IntentFailure> {
    fn leaves(
        value: &Value,
        path: &str,
        fields: &mut std::collections::BTreeSet<String>,
    ) -> Result<(), IntentFailure> {
        match value {
            Value::String(text) if !text.trim().is_empty() => {
                fields.insert(path.to_owned());
            }
            Value::Array(array) => {
                for (i, value) in array.iter().enumerate() {
                    leaves(value, &format!("{path}/{i}"), fields)?;
                }
            }
            Value::Object(map) => {
                for (key, value) in map {
                    leaves(value, &format!("{path}/{key}"), fields)?;
                }
            }
            _ => return Err(IntentFailure::Evidence),
        }
        Ok(())
    }
    let draft = draft_of(result);
    let evidence = draft["field_evidence"]
        .as_object()
        .ok_or(IntentFailure::Evidence)?;
    let mut fields = std::collections::BTreeSet::new();
    leaves(&draft["intent"], "", &mut fields)?;
    if evidence.contains_key("")
        || !fields.contains("/goal")
        || fields != evidence.keys().cloned().collect()
        || draft["source"]["sha256"] != digest(task.as_bytes())
        || draft["source"]["source_id"]
            .as_str()
            .is_none_or(str::is_empty)
    {
        return Err(IntentFailure::Evidence);
    }
    for entry in evidence.values() {
        let offset = |key: &str| {
            entry[key]
                .as_u64()
                .and_then(|v| usize::try_from(v).ok())
                .ok_or(IntentFailure::Evidence)
        };
        let quote = task
            .get(offset("start_byte")?..offset("end_byte")?)
            .ok_or(IntentFailure::Evidence)?;
        if quote.is_empty()
            || entry["quote"] != quote
            || entry["quote_sha256"] != digest(quote.as_bytes())
            || entry["source_id"] != draft["source"]["source_id"]
        {
            return Err(IntentFailure::Evidence);
        }
    }
    Ok(())
}

fn understanding(out: &mut impl io::Write, draft: &Value, task: &str) -> Result<(), IntentFailure> {
    writeln!(
        out,
        "\nOriginal task\n  {}\n\nTask understanding (unconfirmed)",
        escape(task)
    )?;
    let evidence = draft["field_evidence"]
        .as_object()
        .ok_or(IntentFailure::Response)?;
    for (field, entry) in evidence {
        let value = draft["intent"]
            .pointer(field)
            .and_then(Value::as_str)
            .ok_or(IntentFailure::Response)?;
        writeln!(
            out,
            "  {}: {}\n    Task quote: \"{}\"",
            field_label(field),
            escape(
                if field.starts_with("/requested_actions/")
                    || field.starts_with("/prohibitions/")
                    || (field.starts_with("/read_selectors/") && field.ends_with("/kind"))
                {
                    label(value)
                } else {
                    value
                }
            ),
            escape(string(entry, "quote")?)
        )?;
    }
    writeln!(
        out,
        "  Quotes prove textual presence, not correct understanding or authorization."
    )?;
    Ok(())
}

fn field_label(field: &str) -> &'static str {
    match field {
        "/goal" => "Goal",
        f if f.starts_with("/resources/read/") => "Input resource",
        f if f.starts_with("/resources/write/") => "Write target",
        f if f.starts_with("/resources/egress/") => "Egress target",
        f if f.starts_with("/read_selectors/") && f.ends_with("/kind") => "Resource type",
        f if f.starts_with("/read_selectors/") => "Resource name",
        f if f.starts_with("/requested_actions/") => "Requested action",
        f if f.starts_with("/prohibitions/") => "User prohibition",
        f if f.starts_with("/assumptions/") => "Reasoning assumption",
        f if f.starts_with("/unresolved/") => "Clarification",
        f if f.starts_with("/observed_only/") => "Result requirement",
        _ => "External influence",
    }
}

fn label(value: &str) -> &str {
    match value {
        "read" | "filesystem.read" => "Read file contents",
        "directory_listing" | "filesystem.list" => "List directory entries",
        "metadata" | "filesystem.metadata" => "Inspect file types and metadata",
        "current_directory" => "Caller current directory",
        "directory" => "Directory",
        "file" => "File",
        "attachment" => "Attachment",
        "changes" => "Worktree changes",
        "file_mutation" => "Create, edit or delete files",
        "process_execution" => "Run commands or scripts",
        "network_access" => "Access the network",
        "remote_publication" => "Publish to an external destination",
        other => other,
    }
}

fn issue_label(reason: &str) -> &str {
    match reason {
        "missing_working_directory" => {
            "Caller working directory is missing; update the CLI or plugin. The daemon directory cannot replace it."
        }
        "incomplete_directory" => {
            "Reading directory contents requires a complete material snapshot; listing entries does not."
        }
        "invalid_directory" => "Directory binding is indeterminate; provide a normalized path.",
        "unsupported_scope" => "The resource type does not support directory operations.",
        "missing_resource" => {
            "Required materials are missing; supply them explicitly with --attach or --workspace."
        }
        "ambiguous_resource" => "Multiple resources match; select one explicitly.",
        "conflicting_requirements" => "Requested actions conflict with user prohibitions.",
        "unresolved_requirements" => "Some task requirements still need clarification.",
        "missing_read_scope" => "Requested actions and resource scopes do not agree.",
        other => other,
    }
}

pub(super) fn view(candidate: &Value, cedar: bool) -> Result<(), IntentFailure> {
    let mut out = io::stdout().lock();
    if cedar {
        for line in string(candidate, "policy_set")?.lines() {
            writeln!(out, "{}", escape(line))?;
        }
    } else {
        directory_scope(&mut out, candidate)?;
        for read in candidate["reads"]
            .as_array()
            .ok_or(IntentFailure::Response)?
        {
            writeln!(
                out,
                "{}",
                escape(
                    &serde_json::to_string(&read["object"]).map_err(|_| IntentFailure::Response)?
                )
            )?;
        }
    }
    out.flush()?;
    Ok(())
}

pub(super) fn approval_request(
    candidate: &Value,
    mut out: impl io::Write,
    mut diagnostics: impl io::Write,
) -> Result<(), IntentFailure> {
    let request = json!({"decision":"request_approval", "candidate":candidate,
        "candidate_hash":candidate["candidate_hash"], "binding_snapshot_digest":candidate["binding_snapshot_digest"],
        "expires_at":candidate["expires_at"]});
    writeln!(out, "{}", terminal_json(&request)?)?;
    out.flush()?;
    writeln!(
        diagnostics,
        "Approval request generated; not approved or effective. Trusted approval service is not connected."
    )?;
    Ok(())
}

fn terminal_json(value: &Value) -> Result<String, IntentFailure> {
    let encoded = serde_json::to_string(value).map_err(|_| IntentFailure::Response)?;
    Ok(encoded
        .chars()
        .map(|ch| {
            if direction_control(ch) {
                format!("\\u{:04x}", u32::from(ch))
            } else {
                ch.to_string()
            }
        })
        .collect())
}

fn direction_control(ch: char) -> bool {
    matches!(ch, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

pub(super) fn escape(text: &str) -> String {
    text.chars()
        .flat_map(|ch| {
            if ch.is_control() || direction_control(ch) {
                ch.escape_unicode().collect::<Vec<_>>()
            } else {
                vec![ch]
            }
        })
        .collect()
}

/// Groups a Cedar action name into the capability label shown in the text view.
fn category(action: &str) -> &'static str {
    match action {
        "filesystem.read" => "read",
        "filesystem.execute" | "process.spawn" => "execute",
        "network.use" => "network",
        "tool.invoke" => "tools",
        action if action.starts_with("filesystem.") => "write",
        _ => "other",
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn hash(value: &Value) -> Result<String, IntentFailure> {
    fn sort(value: &mut Value) {
        match value {
            Value::Object(map) => {
                map.sort_keys();
                for value in map.values_mut() {
                    sort(value);
                }
            }
            Value::Array(values) => {
                for value in values {
                    sort(value);
                }
            }
            _ => {}
        }
    }
    let mut value = value.clone();
    sort(&mut value);
    Ok(digest(
        &serde_json::to_vec(&value).map_err(|_| IntentFailure::Response)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_or_unflushed_approval_output_never_reports_delivery() {
        struct FailingOutput {
            bytes: Vec<u8>,
            remaining: usize,
        }
        impl io::Write for FailingOutput {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if self.remaining == 0 {
                    return Err(io::ErrorKind::BrokenPipe.into());
                }
                let count = bytes.len().min(self.remaining);
                self.bytes.extend_from_slice(&bytes[..count]);
                self.remaining -= count;
                Ok(count)
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        let candidate = json!({"status":"CANDIDATE", "candidate_hash":"fixture", "binding_snapshot_digest":"binding", "expires_at":2_000_000_000});
        for remaining in [0, 32, usize::MAX] {
            let mut out = FailingOutput {
                bytes: Vec::new(),
                remaining,
            };
            let mut diagnostics = Vec::new();
            assert!(matches!(
                approval_request(&candidate, &mut out, &mut diagnostics),
                Err(IntentFailure::Output)
            ));
            assert!(diagnostics.is_empty());
            if remaining == usize::MAX {
                assert_eq!(
                    serde_json::from_slice::<Value>(&out.bytes).unwrap()["candidate"],
                    candidate
                );
            } else {
                assert_eq!(out.bytes.len(), remaining);
            }
        }
    }

    #[test]
    fn evidence_requires_exact_original_bytes_and_semantic_field_keys() {
        let task = "当前目录下有几个文件";
        let draft = json!({"source":{"source_id":"task-source", "sha256":digest(task.as_bytes())},
            "intent":{"goal":task}, "field_evidence":{"/goal":{
                "source_id":"task-source", "start_byte":0, "end_byte":task.len(),
                "quote":task, "quote_sha256":digest(task.as_bytes())}}});
        let result = |draft| IntentProposeResult::Rejected {
            draft,
            reason: asc_daemon_protocol::intent::IntentRejection::UnsupportedRequest,
        };
        assert!(validate_evidence(&result(draft.clone()), task).is_ok());
        for case in [
            "empty",
            "missing",
            "quote",
            "hash",
            "utf8",
            "range",
            "source",
            "null_source",
        ] {
            let mut bad = draft.clone();
            match case {
                "empty" => {
                    let entry = bad["field_evidence"]["/goal"].clone();
                    bad["field_evidence"]
                        .as_object_mut()
                        .unwrap()
                        .remove("/goal");
                    bad["field_evidence"][""] = entry;
                }
                "missing" => bad["field_evidence"] = json!({}),
                "quote" => bad["field_evidence"]["/goal"]["quote"] = json!("伪造引用"),
                "hash" => bad["field_evidence"]["/goal"]["quote_sha256"] = json!("forged"),
                "utf8" => bad["field_evidence"]["/goal"]["start_byte"] = json!(1),
                "range" => bad["field_evidence"]["/goal"]["end_byte"] = json!(task.len() + 1),
                "source" => bad["field_evidence"]["/goal"]["source_id"] = json!("another"),
                "null_source" => {
                    bad["source"]["source_id"] = Value::Null;
                    bad["field_evidence"]["/goal"]["source_id"] = Value::Null;
                }
                _ => unreachable!(),
            }
            assert!(
                matches!(
                    validate_evidence(&result(bad), task),
                    Err(IntentFailure::Evidence)
                ),
                "{case}"
            );
        }
    }

    #[test]
    fn understanding_translates_only_enums_not_resource_names_or_goals() {
        let draft = json!({"intent":{"goal":"read", "resources":{"read":["read"]},
            "requested_actions":["read"]}, "field_evidence":{
                "/goal":{"quote":"read"}, "/resources/read/0":{"quote":"read"},
                "/requested_actions/0":{"quote":"read"}}});
        let mut out = Vec::new();
        understanding(&mut out, &draft, "read").unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Goal: read"));
        assert!(text.contains("Input resource: read"));
        assert!(text.contains("Requested action: Read file contents"));
        assert!(text.is_ascii());
    }

    #[test]
    fn directory_bindings_must_match_selectors_cwd_and_exact_permissions() {
        let mut candidate = json!({"profile":"directory-inspection@1", "forbidden_actions":["filesystem.read"],
            "draft":{"intent":{"requested_actions":["directory_listing","metadata"],
                "resources":{"read":["当前目录"]}, "read_selectors":[{"kind":"current_directory"}]}},
            "directories":[{"path":"/caller", "requested_as":["当前目录"],
                "permissions":["filesystem.list","filesystem.metadata"]}]});
        assert!(validate_directories(&candidate, "/caller").is_ok());
        for case in [
            "path",
            "missing",
            "permissions",
            "references",
            "profile",
            "forbid",
        ] {
            let mut bad = candidate.clone();
            match case {
                "path" => bad["directories"][0]["path"] = json!("/daemon"),
                "missing" => bad["directories"] = json!([]),
                "permissions" => bad["directories"][0]["permissions"] = json!(["filesystem.list"]),
                "references" => bad["directories"][0]["requested_as"] = json!([]),
                "profile" => bad["profile"] = json!("readonly@1"),
                "forbid" => bad["forbidden_actions"] = json!([]),
                _ => unreachable!(),
            }
            assert!(validate_directories(&bad, "/caller").is_err(), "{case}");
        }
        candidate["draft"]["intent"]["read_selectors"][0] =
            json!({"kind":"directory", "name":"./docs"});
        candidate["directories"][0]["path"] = json!("/caller/docs");
        assert!(validate_directories(&candidate, "/caller").is_ok());
        candidate["draft"]["intent"]["read_selectors"][0]["name"] = json!("../docs");
        assert!(validate_directories(&candidate, "/caller").is_err());
    }

    #[test]
    fn terminal_sequences_and_bidi_are_visible_not_executed() {
        let value = escape("x\x1b[2J\n[approve]\u{202e}\u{2066}");
        assert!(!value.chars().any(char::is_control));
        assert!(!value.contains('\u{202e}'));
        assert!(value.contains("\\u{1b}"));
        let original = json!({"text":"x\u{202e}\u{2066}\u{1b}"});
        let encoded = terminal_json(&original).unwrap();
        assert!(!encoded.contains('\u{202e}'));
        assert_eq!(serde_json::from_str::<Value>(&encoded).unwrap(), original);
    }
}
