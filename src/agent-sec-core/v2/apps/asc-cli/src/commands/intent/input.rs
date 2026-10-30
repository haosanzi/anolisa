//! Bounded collection under the CLI user's permissions, using no-follow traversal without task interpretation.

use std::collections::BTreeSet;
use std::fs::{File, Metadata};
use std::io::{self, Read as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use asc_daemon_protocol::intent::{
    INTENT_MATERIAL_BYTES, INTENT_OBJECTS, IntentMaterial, IntentMaterialVersion, IntentScope,
    IntentScopeKind,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rustix::fs::{Dir, Mode, OFlags, open, openat};

use super::git;

#[derive(Debug, thiserror::Error)]
pub(super) enum InputFailure {
    #[error("input exceeds collection budget; use smaller explicit --attach inputs")]
    Limit,
    #[error(
        "input is unsupported, inaccessible or changed during collection; use regular files without symlinks"
    )]
    Unsafe,
    #[error("{0}")]
    Clarification(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Collected {
    pub working_directory: String,
    pub scopes: Vec<IntentScope>,
    pub materials: Vec<IntentMaterial>,
}

pub(super) struct Budget {
    deadline: Instant,
    scanned: usize,
    material_bytes: usize,
    pub objects: usize,
    entries: usize,
    observations: Vec<(PathBuf, Metadata)>,
}

impl Budget {
    fn new() -> Self {
        Self {
            deadline: Instant::now() + Duration::from_secs(5),
            scanned: 0,
            material_bytes: 0,
            objects: 0,
            entries: 0,
            observations: Vec::new(),
        }
    }

    pub fn check(&self) -> Result<(), InputFailure> {
        if Instant::now() >= self.deadline {
            Err(InputFailure::Limit)
        } else {
            Ok(())
        }
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn scan(&mut self, bytes: usize) -> Result<(), InputFailure> {
        self.check()?;
        self.scanned = self.scanned.checked_add(bytes).ok_or(InputFailure::Limit)?;
        if self.scanned > 64 * 1024 * 1024 {
            return Err(InputFailure::Limit);
        }
        Ok(())
    }

    pub fn material(
        &mut self,
        scope: &str,
        path: String,
        version: IntentMaterialVersion,
        content: &[u8],
    ) -> Result<IntentMaterial, InputFailure> {
        self.check()?;
        self.objects += 1;
        self.material_bytes += content.len();
        if self.objects > INTENT_OBJECTS || self.material_bytes > INTENT_MATERIAL_BYTES {
            return Err(InputFailure::Limit);
        }
        Ok(IntentMaterial {
            scope: scope.into(),
            path,
            version,
            content_base64: STANDARD.encode(content),
        })
    }
}

pub(super) fn collect(
    workspace: Option<&Path>,
    attachments: &[PathBuf],
) -> Result<Collected, InputFailure> {
    let mut budget = Budget::new();
    let cwd = std::env::current_dir().map_err(|_| InputFailure::Unsafe)?;
    let working_directory = cwd.to_str().ok_or(InputFailure::Unsafe)?.to_owned();
    if working_directory != "/" {
        valid_relative(working_directory.trim_start_matches('/'))?;
    }
    let mut result = Collected {
        working_directory,
        scopes: vec![],
        materials: vec![],
    };
    let mut seen = BTreeSet::new();
    for path in attachments {
        let path = absolute(path)?;
        if !seen.insert(path.clone()) {
            continue;
        }
        let mut file = open_path(&path).map_err(|_| InputFailure::Unsafe)?;
        let metadata = file.metadata().map_err(|_| InputFailure::Unsafe)?;
        let scope = scope_name(&path)?;
        if metadata.is_dir() {
            result.scopes.push(IntentScope {
                name: scope.clone(),
                kind: IntentScopeKind::Directory,
                base: None,
            });
            directory(&file, &scope, &scope, &mut budget, &mut result.materials, 0)?;
        } else {
            let bytes = read_file(&mut file, INTENT_MATERIAL_BYTES, &mut budget)?;
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(InputFailure::Unsafe)?
                .to_owned();
            result.scopes.push(IntentScope {
                name: scope.clone(),
                kind: IntentScopeKind::Attachment,
                base: None,
            });
            result.materials.push(budget.material(
                &scope,
                name,
                IntentMaterialVersion::Current,
                &bytes,
            )?);
        }
        let after = open_path(&path)
            .and_then(|file| file.metadata())
            .map_err(|_| InputFailure::Unsafe)?;
        if !unchanged(&metadata, &after) {
            return Err(InputFailure::Unsafe);
        }
        budget.observations.push((path, metadata));
    }
    // Collect Git last, then recheck attachments to avoid a full traversal after worktree checks.
    if let Some(workspace) = workspace {
        git::collect(workspace, &mut budget, &mut result)?;
    }
    result.scopes.sort_by(|a, b| a.name.cmp(&b.name));
    result
        .materials
        .sort_by(|a, b| (&a.scope, &a.path, a.version).cmp(&(&b.scope, &b.path, b.version)));
    if result.scopes.len() > INTENT_OBJECTS
        || result
            .scopes
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
    {
        return Err(InputFailure::Unsafe);
    }
    let metadata_size: usize = result
        .scopes
        .iter()
        .map(|scope| scope.name.len() + scope.base.as_ref().map_or(0, String::len))
        .sum::<usize>()
        + result
            .materials
            .iter()
            .map(|material| material.scope.len() + material.path.len() + 512)
            .sum::<usize>();
    if metadata_size > 256 * 1024 {
        return Err(InputFailure::Limit);
    }
    for (path, before) in &budget.observations {
        budget.check()?;
        let after = open_path(path)
            .and_then(|file| file.metadata())
            .map_err(|_| InputFailure::Unsafe)?;
        if !unchanged(before, &after) {
            return Err(InputFailure::Unsafe);
        }
    }
    budget.check()?;
    Ok(result)
}

fn directory(
    dir: &File,
    scope: &str,
    prefix: &str,
    budget: &mut Budget,
    materials: &mut Vec<IntentMaterial>,
    depth: usize,
) -> Result<(), InputFailure> {
    budget.check()?;
    if depth > 64 {
        return Err(InputFailure::Limit);
    }
    let before = dir.metadata().map_err(|_| InputFailure::Unsafe)?;
    let entries = Dir::read_from(dir).map_err(|_| InputFailure::Unsafe)?;
    let mut count = 0;
    for entry in entries {
        budget.check()?;
        let entry = entry.map_err(|_| InputFailure::Unsafe)?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| InputFailure::Unsafe)?;
        if name == "." || name == ".." {
            continue;
        }
        count += 1;
        budget.entries += 1;
        if count > INTENT_OBJECTS || budget.entries > 65_536 {
            return Err(InputFailure::Limit);
        }
        valid_relative(name)?;
        let mut file = open_child(dir, Path::new(name)).map_err(|_| InputFailure::Unsafe)?;
        let metadata = file.metadata().map_err(|_| InputFailure::Unsafe)?;
        let path = format!("{prefix}/{name}");
        if metadata.is_dir() {
            directory(&file, scope, &path, budget, materials, depth + 1)?;
        } else {
            let bytes = read_file(&mut file, INTENT_MATERIAL_BYTES, budget)?;
            materials.push(budget.material(
                scope,
                path.clone(),
                IntentMaterialVersion::Current,
                &bytes,
            )?);
        }
        let after = open_child(dir, Path::new(name))
            .and_then(|file| file.metadata())
            .map_err(|_| InputFailure::Unsafe)?;
        if !unchanged(&metadata, &after) {
            return Err(InputFailure::Unsafe);
        }
        budget
            .observations
            .push((PathBuf::from(format!("/{path}")), metadata));
    }
    if !unchanged(&before, &dir.metadata().map_err(|_| InputFailure::Unsafe)?) {
        return Err(InputFailure::Unsafe);
    }
    Ok(())
}

pub(super) fn absolute(path: &Path) -> Result<PathBuf, InputFailure> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(InputFailure::Unsafe);
    }
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| InputFailure::Unsafe)?
            .join(path)
    };
    let normalized: PathBuf = path
        .components()
        .filter(|component| !matches!(component, Component::CurDir))
        .collect();
    scope_name(&normalized)?;
    Ok(normalized)
}

pub(super) fn scope_name(path: &Path) -> Result<String, InputFailure> {
    let name = path
        .strip_prefix("/")
        .map_err(|_| InputFailure::Unsafe)?
        .to_str()
        .ok_or(InputFailure::Unsafe)?;
    valid_relative(name)?;
    Ok(name.to_owned())
}

pub(super) fn valid_relative(path: &str) -> Result<(), InputFailure> {
    if path.is_empty()
        || path.len() > 4096
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(InputFailure::Unsafe);
    }
    Ok(())
}

pub(super) fn open_path(path: &Path) -> io::Result<File> {
    let root: File = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into();
    open_child(&root, path.strip_prefix("/").map_err(io::Error::other)?)
}

pub(super) fn open_child(root: &File, path: &Path) -> io::Result<File> {
    let mut dir = root.try_clone()?;
    let parts: Vec<_> = path.components().collect();
    for (index, component) in parts.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(io::Error::other("invalid path component"));
        };
        let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK;
        if index + 1 < parts.len() {
            flags |= OFlags::DIRECTORY;
        }
        dir = openat(&dir, *name, flags, Mode::empty())?.into();
    }
    Ok(dir)
}

pub(super) fn read_file(
    file: &mut File,
    limit: usize,
    budget: &mut Budget,
) -> Result<Vec<u8>, InputFailure> {
    budget.check()?;
    let before = file.metadata().map_err(|_| InputFailure::Unsafe)?;
    if !before.is_file() {
        return Err(InputFailure::Unsafe);
    }
    let length = usize::try_from(before.len()).map_err(|_| InputFailure::Limit)?;
    if length > limit {
        return Err(InputFailure::Limit);
    }
    budget.scan(length)?;
    let mut bytes = Vec::with_capacity(length);
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| InputFailure::Unsafe)?;
    budget.check()?;
    if bytes.len() != length
        || !unchanged(&before, &file.metadata().map_err(|_| InputFailure::Unsafe)?)
    {
        return Err(InputFailure::Unsafe);
    }
    Ok(bytes)
}

pub(super) fn unchanged(before: &Metadata, after: &Metadata) -> bool {
    (
        before.dev(),
        before.ino(),
        before.mode(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) == (
        after.dev(),
        after.ino(),
        after.mode(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::ffi::OsStringExt as _;
    use std::os::unix::fs::symlink;

    #[test]
    fn directories_include_hidden_members_deduplicate_sources_and_keep_siblings() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("a/docs");
        let second = dir.path().join("b/docs");
        for path in [&first, &second] {
            fs::create_dir_all(path).unwrap();
            fs::write(path.join(".hidden"), "private").unwrap();
        }
        let result = collect(None, &[first.clone(), first.clone(), second]).unwrap();
        assert_eq!(result.scopes.len(), 2);
        assert_eq!(result.materials.len(), 2);
        assert!(
            result
                .materials
                .iter()
                .all(|m| m.path.ends_with("/.hidden"))
        );
        assert_ne!(result.scopes[0].name, result.scopes[1].name);
        symlink(dir.path(), first.join("escape")).unwrap();
        assert!(matches!(collect(None, &[first]), Err(InputFailure::Unsafe)));
    }

    #[test]
    fn collection_is_never_silently_truncated() {
        let dir = tempfile::tempdir().unwrap();
        for n in 0..=INTENT_OBJECTS {
            fs::write(dir.path().join(n.to_string()), "").unwrap();
        }
        assert!(matches!(
            collect(None, &[dir.path().into()]),
            Err(InputFailure::Limit)
        ));
        let mut budget = Budget::new();
        budget.deadline = Instant::now();
        assert!(matches!(budget.check(), Err(InputFailure::Limit)));
        for path in ["../outside", "a/../b", "a\\b", "a\u{1b}[2J"] {
            assert!(valid_relative(path).is_err());
        }
    }

    #[test]
    fn metadata_changes_and_unrepresentable_paths_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");
        fs::write(&path, "before").unwrap();
        let before = fs::metadata(&path).unwrap();
        fs::write(&path, "after longer").unwrap();
        assert!(!unchanged(&before, &fs::metadata(&path).unwrap()));
        let invalid = dir.path().join(std::ffi::OsString::from_vec(vec![0xff]));
        fs::write(&invalid, "bad name").unwrap();
        assert!(matches!(
            collect(None, &[invalid]),
            Err(InputFailure::Unsafe)
        ));
    }
}
