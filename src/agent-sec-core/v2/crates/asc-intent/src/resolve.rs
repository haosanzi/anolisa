//! Build content-addressed snapshots from bounded materials and resolve exact resource selections.
//! Only received bytes are processed; host paths are never opened and no authority is implied.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::interpreter::{ReadKind, ReadSelector};
use crate::{ProposalContext, TaskIntentDraft};
use asc_policy_types::filesystem::FilesystemPermission;

/// Maximum material bytes accepted per proposal.
pub const MAX_MATERIAL_BYTES: usize = 1024 * 1024;
/// Maximum material objects accepted per proposal.
pub const MAX_OBJECTS: usize = 256;

/// Material origin, not proof of host identity or approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSource {
    /// Offline test and demo materials.
    Fixture,
    /// Caller-supplied materials with digests recomputed by the generator.
    RequestSnapshot,
}

/// Closed vocabulary of scopes collected by input adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    /// Changes against an explicit base, not the entire workspace.
    Changes,
    /// Explicitly collected complete directory snapshot, excluding future files.
    Directory,
    /// Explicitly supplied file attachments.
    Attachment,
}

/// Input material scope; downstream services must verify completeness before execution.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceScope {
    /// Request-local unique name, not a host path the daemon may open.
    pub name: String,
    /// Kind of collected scope.
    pub kind: ScopeKind,
    /// Immutable base reference for changes; must be absent for other scope kinds.
    pub base: Option<String>,
}

/// Side of a material change; deleted files have only a [`MaterialVersion::Before`] version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterialVersion {
    /// Bytes from the base version.
    Before,
    /// Current snapshot bytes, not a persistent host file handle.
    Current,
}

/// Actual adapter-supplied material; caller-claimed entity IDs and content digests are rejected.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Material {
    /// Request-local name of the corresponding [`ResourceScope`].
    pub scope: String,
    /// Normalized relative path identifying only the received bytes.
    pub path: String,
    /// Whether the material belongs to the base or current version.
    pub version: MaterialVersion,
    /// Received bytes, never sent to the model or embedded in the candidate.
    pub content: Vec<u8>,
}

/// Snapshot object metadata with program-computed identity and digest.
#[derive(Clone, Serialize)]
pub struct SnapshotObject {
    /// Cedar `FilesystemResource` ID derived from the task, scope, path, version and digest.
    pub entity_id: String,
    /// Request-local source scope.
    pub scope: String,
    /// Relative path, not an OS object identity.
    pub path: String,
    /// Base or current version.
    pub version: MaterialVersion,
    /// SHA-256 digest of the received material.
    pub content_sha256: String,
    /// Byte length of the received material.
    pub byte_length: usize,
}

/// Immutable, bounded and unauthorized material snapshot; file contents are not retained.
#[derive(Clone, Serialize)]
pub struct ResourceSnapshot {
    pub(crate) task_id: String,
    source: SnapshotSource,
    scopes: BTreeMap<String, ResourceScope>,
    objects: Vec<SnapshotObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    working_directory: Option<String>,
    digest: String,
}

impl ResourceSnapshot {
    /// Validate materials and recompute object and snapshot digests without trusting caller claims.
    ///
    /// # Errors
    /// Returns an error for oversized input, non-normalized paths, conflicting scopes
    /// or missing change bases.
    pub fn new(
        context: &ProposalContext,
        source: SnapshotSource,
        scopes: Vec<ResourceScope>,
        materials: Vec<Material>,
    ) -> Result<Self, SnapshotError> {
        if scopes.len() > MAX_OBJECTS || materials.len() > MAX_OBJECTS {
            return Err(SnapshotError::TooLarge);
        }
        let mut scope_map = BTreeMap::new();
        for scope in scopes {
            if !relative_path(&scope.name)
                || match (&scope.kind, &scope.base) {
                    (ScopeKind::Changes, Some(base)) => !stable_id(base),
                    (ScopeKind::Changes, None) | (_, Some(_)) => true,
                    (_, None) => false,
                }
                || scope_map.insert(scope.name.clone(), scope).is_some()
            {
                return Err(SnapshotError::InvalidScope);
            }
        }
        let mut total = 0_usize;
        let mut keys = BTreeSet::new();
        let mut objects = Vec::with_capacity(materials.len());
        for material in materials {
            total = total
                .checked_add(material.content.len())
                .ok_or(SnapshotError::TooLarge)?;
            if total > MAX_MATERIAL_BYTES {
                return Err(SnapshotError::TooLarge);
            }
            let scope = scope_map
                .get(&material.scope)
                .ok_or(SnapshotError::InvalidScope)?;
            if !relative_path(&material.path)
                || (scope.kind == ScopeKind::Directory && !under(&material.path, &scope.name))
                || (scope.kind != ScopeKind::Changes
                    && material.version != MaterialVersion::Current)
                || !keys.insert((
                    material.scope.clone(),
                    material.path.clone(),
                    material.version,
                ))
            {
                return Err(SnapshotError::InvalidMaterial);
            }
            let content_sha256 = digest_bytes(&material.content);
            let identity = canonical_hash(&(
                &context.task_id,
                &material.scope,
                &material.path,
                material.version,
                &content_sha256,
            ))?;
            objects.push(SnapshotObject {
                entity_id: identity.replace("sha256:", "file-"),
                scope: material.scope,
                path: material.path,
                version: material.version,
                content_sha256,
                byte_length: material.content.len(),
            });
        }
        if objects.iter().any(|parent| {
            objects.iter().any(|child| {
                parent.scope == child.scope
                    && parent.version == child.version
                    && under(&child.path, &parent.path)
            })
        }) {
            return Err(SnapshotError::InvalidMaterial);
        }
        objects.sort_by(|left, right| left.entity_id.cmp(&right.entity_id));
        let digest = canonical_hash(&(&context.task_id, source, &scope_map, &objects))?;
        let snapshot = Self {
            task_id: context.task_id.clone(),
            source,
            scopes: scope_map,
            objects,
            working_directory: None,
            digest,
        };
        let encoded = serde_json::to_vec(&snapshot).map_err(|_| SnapshotError::Encoding)?;
        if encoded.len() > 256 * 1024 {
            return Err(SnapshotError::TooLarge);
        }
        Ok(snapshot)
    }

    /// Record caller-namespace cwd without reading daemon host paths or granting authority.
    ///
    /// # Errors
    /// Rejects non-normalized absolute paths, oversized metadata or encoding failures;
    /// never guesses a path or substitutes the daemon's cwd.
    pub fn with_working_directory(mut self, cwd: String) -> Result<Self, SnapshotError> {
        if !absolute_path(&cwd) {
            return Err(SnapshotError::InvalidScope);
        }
        self.working_directory = Some(cwd);
        self.digest = canonical_hash(&(
            &self.task_id,
            self.source,
            &self.scopes,
            &self.objects,
            &self.working_directory,
        ))?;
        if serde_json::to_vec(&self)
            .map_err(|_| SnapshotError::Encoding)?
            .len()
            > 256 * 1024
        {
            return Err(SnapshotError::TooLarge);
        }
        Ok(self)
    }

    /// Caller-supplied directory context, not yet bound to an enforcement-side OS object.
    pub fn working_directory(&self) -> Option<&str> {
        self.working_directory.as_deref()
    }

    /// Source kind, not an identity or authorization label.
    pub fn source(&self) -> SnapshotSource {
        self.source
    }

    /// Digest covering all objects, scopes, provenance and change bases.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Material metadata sorted by entity ID, without file contents.
    pub fn objects(&self) -> &[SnapshotObject] {
        &self.objects
    }
}

/// Snapshot failures that omit paths, contents and other sensitive inputs.
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// Object count, metadata or contents exceed the budget.
    #[error("resource snapshot exceeds its size limit")]
    TooLarge,
    /// Scope names, kinds, change bases or references are inconsistent.
    #[error("invalid or conflicting resource scope")]
    InvalidScope,
    /// Paths, versions or object uniqueness violate snapshot constraints.
    #[error("invalid or duplicate snapshot material")]
    InvalidMaterial,
    /// Typed data could not be serialized canonically.
    #[error("resource snapshot encoding failed")]
    Encoding,
}

/// Request for additional materials or scope selection, containing no candidate permits.
#[derive(Serialize)]
pub struct ResourceIssue {
    /// Verbatim scope reference from the task.
    pub requested_as: String,
    /// Missing, ambiguous or incomplete scope.
    pub reason: ResourceIssueKind,
    /// Source-qualified names the user can explicitly select.
    pub alternatives: Vec<String>,
}

/// Closed vocabulary of resource clarification reasons.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceIssueKind {
    /// Material is missing or the selection kind conflicts with the supplied scope.
    MissingResource,
    /// Multiple objects match; none may be selected by default.
    AmbiguousResource,
    /// No complete directory was supplied; change materials cannot replace it.
    IncompleteDirectory,
    /// Caller cwd is missing; the daemon's directory must not replace it.
    MissingWorkingDirectory,
    /// The directory selector is not a normalized, deterministically bindable path.
    InvalidDirectory,
    /// The requested object type cannot support directory operations.
    UnsupportedScope,
}

#[derive(Serialize)]
pub(crate) struct ResolvedRead {
    pub(crate) object: SnapshotObject,
    pub(crate) requested_as: BTreeSet<String>,
}

#[derive(Serialize)]
pub(crate) struct ResolvedDirectory {
    pub(crate) entity_id: String,
    pub(crate) path: String,
    pub(crate) requested_as: BTreeSet<String>,
    pub(crate) permissions: BTreeSet<FilesystemPermission>,
}

pub(crate) fn resolve_directories(
    draft: &TaskIntentDraft,
    snapshot: &ResourceSnapshot,
    permissions: &BTreeSet<FilesystemPermission>,
) -> Result<Vec<ResolvedDirectory>, Vec<ResourceIssue>> {
    let mut directories: BTreeMap<String, ResolvedDirectory> = BTreeMap::new();
    let mut issues = Vec::new();
    for (raw, selector) in draft.read_resources().iter().zip(draft.read_selectors()) {
        let path = directory_path(selector, snapshot);
        match path {
            Ok(path) => {
                let identity = canonical_hash(&(&snapshot.task_id, "directory", &path));
                let Ok(identity) = identity else {
                    issues.push(ResourceIssue {
                        requested_as: raw.clone(),
                        reason: ResourceIssueKind::InvalidDirectory,
                        alternatives: vec![],
                    });
                    continue;
                };
                directories
                    .entry(path.clone())
                    .or_insert_with(|| ResolvedDirectory {
                        entity_id: identity.replace("sha256:", "directory-"),
                        path,
                        requested_as: BTreeSet::new(),
                        permissions: permissions.clone(),
                    })
                    .requested_as
                    .insert(raw.clone());
            }
            Err(reason) => issues.push(ResourceIssue {
                requested_as: raw.clone(),
                reason,
                alternatives: vec![],
            }),
        }
    }
    if issues.is_empty() {
        Ok(directories.into_values().collect())
    } else {
        Err(issues)
    }
}

fn directory_path(
    selector: &ReadSelector,
    snapshot: &ResourceSnapshot,
) -> Result<String, ResourceIssueKind> {
    if selector.kind == ReadKind::CurrentDirectory {
        return snapshot
            .working_directory
            .clone()
            .ok_or(ResourceIssueKind::MissingWorkingDirectory);
    }
    if selector.kind != ReadKind::Directory {
        return Err(ResourceIssueKind::UnsupportedScope);
    }
    let name = selector
        .name
        .as_deref()
        .ok_or(ResourceIssueKind::InvalidDirectory)?;
    if absolute_path(name) {
        return Ok(name.to_owned());
    }
    let relative = name.strip_prefix("./").unwrap_or(name);
    if name != "." && !relative_path(relative) {
        return Err(ResourceIssueKind::InvalidDirectory);
    }
    let cwd = snapshot
        .working_directory()
        .ok_or(ResourceIssueKind::MissingWorkingDirectory)?;
    if name == "." {
        return Ok(cwd.to_owned());
    }
    let path = format!("{}/{relative}", cwd.trim_end_matches('/'));
    if !absolute_path(&path) {
        return Err(ResourceIssueKind::InvalidDirectory);
    }
    Ok(path)
}

fn absolute_path(path: &str) -> bool {
    path.len() <= 4096 && (path == "/" || path.strip_prefix('/').is_some_and(relative_path))
}

pub(crate) fn resolve(
    draft: &TaskIntentDraft,
    snapshot: &ResourceSnapshot,
) -> Result<Vec<ResolvedRead>, Vec<ResourceIssue>> {
    let mut reads: BTreeMap<String, ResolvedRead> = BTreeMap::new();
    let mut issues = Vec::new();
    for (raw, selector) in draft.read_resources().iter().zip(draft.read_selectors()) {
        match select(selector, snapshot) {
            Ok(objects) => {
                for object in objects {
                    reads
                        .entry(object.entity_id.clone())
                        .or_insert_with(|| ResolvedRead {
                            object: object.clone(),
                            requested_as: BTreeSet::new(),
                        })
                        .requested_as
                        .insert(raw.clone());
                }
            }
            Err((reason, alternatives)) => issues.push(ResourceIssue {
                requested_as: raw.clone(),
                reason,
                alternatives,
            }),
        }
    }
    if issues.is_empty() {
        Ok(reads.into_values().collect())
    } else {
        Err(issues)
    }
}

fn select<'a>(
    selector: &ReadSelector,
    snapshot: &'a ResourceSnapshot,
) -> Result<Vec<&'a SnapshotObject>, (ResourceIssueKind, Vec<String>)> {
    if selector.kind == ReadKind::CurrentDirectory {
        let cwd = snapshot
            .working_directory()
            .ok_or((ResourceIssueKind::MissingWorkingDirectory, vec![]))?;
        return select(
            &ReadSelector {
                kind: ReadKind::Directory,
                name: Some(cwd.trim_start_matches('/').into()),
            },
            snapshot,
        );
    }
    if selector.kind != ReadKind::Changes
        && let Some(name) = &selector.name
        && snapshot
            .scopes
            .values()
            .any(|scope| scope.kind == ScopeKind::Directory && scope_matches(name, &scope.name))
    {
        let files: Vec<_> = snapshot
            .objects
            .iter()
            .filter(|object| {
                object.version == MaterialVersion::Current && scope_matches(name, &object.path)
            })
            .map(|object| format!("{}/{}", object.scope, object.path))
            .collect();
        if !files.is_empty() {
            let mut alternatives = vec![format!("{name}/")];
            alternatives.extend(files);
            return Err((ResourceIssueKind::AmbiguousResource, alternatives));
        }
    }
    if matches!(selector.kind, ReadKind::Changes | ReadKind::Directory) {
        let scopes: Vec<_> = snapshot
            .scopes
            .values()
            .filter(|scope| match selector.kind {
                ReadKind::Changes => {
                    scope.kind == ScopeKind::Changes
                        && selector
                            .name
                            .as_ref()
                            .is_none_or(|name| scope_matches(name, &scope.name))
                }
                ReadKind::Directory => {
                    scope.kind == ScopeKind::Directory
                        && selector
                            .name
                            .as_ref()
                            .is_some_and(|name| directory_selection(name, &scope.name).is_some())
                }
                _ => false,
            })
            .collect();
        if scopes.len() > 1 {
            return Err((
                ResourceIssueKind::AmbiguousResource,
                scopes.iter().map(|scope| scope.name.clone()).collect(),
            ));
        }
        let Some(scope) = scopes.first() else {
            return Err((
                if selector.kind == ReadKind::Directory {
                    ResourceIssueKind::IncompleteDirectory
                } else {
                    ResourceIssueKind::MissingResource
                },
                Vec::new(),
            ));
        };
        let objects: Vec<_> = snapshot
            .objects
            .iter()
            .filter(|object| {
                object.scope == scope.name
                    && (selector.kind == ReadKind::Changes
                        || selector
                            .name
                            .as_ref()
                            .and_then(|name| directory_selection(name, &scope.name))
                            .is_some_and(|name| under(&object.path, &name)))
            })
            .collect();
        return if objects.is_empty() {
            Err((ResourceIssueKind::MissingResource, Vec::new()))
        } else {
            Ok(objects)
        };
    }
    select_file(selector, snapshot)
}

fn select_file<'a>(
    selector: &ReadSelector,
    snapshot: &'a ResourceSnapshot,
) -> Result<Vec<&'a SnapshotObject>, (ResourceIssueKind, Vec<String>)> {
    let Some(name) = selector.name.as_deref().filter(|name| relative_path(name)) else {
        return Err((ResourceIssueKind::MissingResource, Vec::new()));
    };
    let eligible: Vec<_> = snapshot
        .objects
        .iter()
        .filter(|object| {
            object.version == MaterialVersion::Current
                && (selector.kind != ReadKind::Attachment
                    || snapshot
                        .scopes
                        .get(&object.scope)
                        .is_some_and(|scope| scope.kind == ScopeKind::Attachment))
        })
        .collect();
    let matches: Vec<_> = eligible
        .into_iter()
        .filter(|object| {
            if name.contains('/') {
                object.path == name || format!("{}/{}", object.scope, object.path) == name
            } else {
                object.path.rsplit('/').next() == Some(name)
            }
        })
        .collect();
    match matches.len() {
        0 => Err((ResourceIssueKind::MissingResource, Vec::new())),
        1 => Ok(matches),
        _ => Err((
            ResourceIssueKind::AmbiguousResource,
            matches
                .iter()
                .map(|object| format!("{}/{}", object.scope, object.path))
                .collect(),
        )),
    }
}

fn scope_matches(name: &str, scope: &str) -> bool {
    name == scope || (!name.contains('/') && scope.rsplit('/').next() == Some(name))
}

fn directory_selection(name: &str, scope: &str) -> Option<String> {
    if !relative_path(name) {
        return None;
    }
    if name == scope || under(name, scope) {
        return Some(name.into());
    }
    let basename = scope.rsplit('/').next()?;
    if name == basename {
        return Some(scope.into());
    }
    name.strip_prefix(basename)
        .filter(|tail| tail.starts_with('/'))
        .map(|tail| format!("{scope}{tail}"))
}

fn under(path: &str, directory: &str) -> bool {
    path.strip_prefix(directory)
        .is_some_and(|tail| tail.starts_with('/'))
}

fn relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

pub(crate) fn stable_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

pub(crate) fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub(crate) fn canonical_hash(value: &impl Serialize) -> Result<String, SnapshotError> {
    fn sort(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(fields) => {
                fields.sort_keys();
                for value in fields.values_mut() {
                    sort(value);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    sort(value);
                }
            }
            _ => {}
        }
    }
    let mut value = serde_json::to_value(value).map_err(|_| SnapshotError::Encoding)?;
    sort(&mut value);
    let bytes = serde_json::to_vec(&value).map_err(|_| SnapshotError::Encoding)?;
    Ok(digest_bytes(&bytes))
}
