//! Allowlisted Git plumbing with isolated configuration for raw HEAD-to-worktree net changes.

use std::collections::BTreeMap;
use std::fs::{self, File, Metadata};
use std::io::{self, Read as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use asc_daemon_protocol::intent::{
    INTENT_MATERIAL_BYTES, IntentMaterialVersion, IntentScope, IntentScopeKind,
};
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};
use rustix::fs::Dir;

use super::input::{
    Budget, Collected, InputFailure, absolute, open_child, open_path, read_file, scope_name,
    unchanged, valid_relative,
};

const LIST_BYTES: usize = 4 * 1024 * 1024;
const RECORDS: usize = 65_536;
const UNSUPPORTED: &str =
    "Git layout is unsupported or objects are missing; provide explicit --attach files";

pub(super) fn collect(
    path: &Path,
    budget: &mut Budget,
    result: &mut Collected,
) -> Result<(), InputFailure> {
    let (root_path, root, git_dir) = repository(path, budget)?;
    let index = metadata_bytes(&git_dir, "index", LIST_BYTES, budget)?.unwrap_or_default();
    validate_index(&index)?;
    let head = head(&git_dir, budget)?;
    for name in [
        "commondir",
        "shallow",
        "objects/info/alternates",
        "objects/info/http-alternates",
        "info/sparse-checkout",
    ] {
        match open_child(&git_dir, Path::new(name)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(InputFailure::Clarification(UNSUPPORTED)),
        }
    }
    // Use generated config and frozen HEAD/index so Git never loads repository config or includes.
    let isolated = tempfile::tempdir().map_err(|_| InputFailure::Unsafe)?;
    fs::create_dir(isolated.path().join("refs")).map_err(|_| InputFailure::Unsafe)?;
    fs::create_dir(isolated.path().join("objects")).map_err(|_| InputFailure::Unsafe)?;
    fs::write(isolated.path().join("HEAD"), format!("{head}\n"))
        .map_err(|_| InputFailure::Unsafe)?;
    if !index.is_empty() {
        fs::write(isolated.path().join("index"), &index).map_err(|_| InputFailure::Unsafe)?;
    }
    fs::write(isolated.path().join("config"), "[core]\nrepositoryformatversion = 0\nbare = true\nfsmonitor = false\nhooksPath = /dev/null\n").map_err(|_| InputFailure::Unsafe)?;
    copy_objects(&git_dir, &isolated.path().join("objects"), budget)?;
    let git = Git {
        metadata: isolated.path(),
    };
    let files = tracked_files(&git, &head, budget)?;
    let scope = scope_name(&root_path)?;
    let initial_count = result.materials.len();
    let observations = collect_changes(&root, &git, files, &scope, budget, result)?;
    if head != self::head(&git_dir, budget)?
        || index != metadata_bytes(&git_dir, "index", LIST_BYTES, budget)?.unwrap_or_default()
    {
        return Err(InputFailure::Unsafe);
    }
    for (path, before) in observations {
        budget.check()?;
        let after = open_child(&root, Path::new(&path)).and_then(|file| file.metadata());
        match (before, after) {
            (Some(before), Ok(after)) if unchanged(&before, &after) => {}
            (None, Err(error)) if error.kind() == io::ErrorKind::NotFound => {}
            _ => return Err(InputFailure::Unsafe),
        }
    }
    let root_after = open_path(&root_path)
        .and_then(|file| file.metadata())
        .map_err(|_| InputFailure::Unsafe)?;
    let root_before = root.metadata().map_err(|_| InputFailure::Unsafe)?;
    if root_before.dev() != root_after.dev() || root_before.ino() != root_after.ino() {
        return Err(InputFailure::Unsafe);
    }
    if result.materials.len() == initial_count {
        return Err(InputFailure::Clarification(
            "No tracked HEAD-to-worktree changes; supply review materials with --attach (untracked files are excluded)",
        ));
    }
    result.scopes.push(IntentScope {
        name: scope,
        kind: IntentScopeKind::Changes,
        base: Some(head),
    });
    Ok(())
}

type TrackedFiles = BTreeMap<String, Option<(String, u32)>>;

fn tracked_files(git: &Git<'_>, head: &str, budget: &Budget) -> Result<TrackedFiles, InputFailure> {
    let tree = git.run(&["ls-tree", "-rz", "--full-tree", head], LIST_BYTES, budget)?;
    let indexed = git.run(&["ls-files", "--stage", "-z"], LIST_BYTES, budget)?;
    let mut files: BTreeMap<String, Option<(String, u32)>> = BTreeMap::new();
    for record in records(&tree)? {
        let (header, path) = record.split_once('\t').ok_or(InputFailure::Unsafe)?;
        let fields: Vec<_> = header.split(' ').collect();
        if fields.len() != 3 || fields[1] != "blob" || !object_id(fields[2]) {
            return Err(InputFailure::Clarification(UNSUPPORTED));
        }
        let mode = file_mode(fields[0])?;
        valid_relative(path)?;
        if files
            .insert(path.into(), Some((fields[2].into(), mode)))
            .is_some()
        {
            return Err(InputFailure::Unsafe);
        }
    }
    for record in records(&indexed)? {
        let (header, path) = record.split_once('\t').ok_or(InputFailure::Unsafe)?;
        let fields: Vec<_> = header.split(' ').collect();
        if fields.len() != 3 || !object_id(fields[1]) {
            return Err(InputFailure::Unsafe);
        }
        if fields[2] != "0" {
            return Err(InputFailure::Clarification(
                "Git has unresolved merge conflicts; resolve them or use --attach",
            ));
        }
        file_mode(fields[0])?;
        valid_relative(path)?;
        files.entry(path.into()).or_default();
    }
    if files.len() > RECORDS {
        return Err(InputFailure::Limit);
    }
    Ok(files)
}

fn collect_changes(
    root: &File,
    git: &Git<'_>,
    files: TrackedFiles,
    scope: &str,
    budget: &mut Budget,
    result: &mut Collected,
) -> Result<Vec<(String, Option<Metadata>)>, InputFailure> {
    let mut observations: Vec<(String, Option<Metadata>)> = Vec::with_capacity(files.len());
    for (path, previous) in files {
        budget.check()?;
        let current = match open_child(root, Path::new(&path)) {
            Ok(mut file) => {
                let stat = file.metadata().map_err(|_| InputFailure::Unsafe)?;
                let bytes = read_file(&mut file, 64 * 1024 * 1024, budget)?;
                Some((stat, bytes))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(_) => return Err(InputFailure::Unsafe),
        };
        let differs = match (&previous, &current) {
            (Some((oid, mode)), Some((stat, bytes))) => {
                blob_id(bytes) != *oid || (stat.mode() & 0o111 != 0) != (*mode == 0o100_755)
            }
            (None, None) => false,
            _ => true,
        };
        if differs {
            if let Some((oid, _)) = previous {
                let before = git.run(&["cat-file", "blob", &oid], INTENT_MATERIAL_BYTES, budget)?;
                if blob_id(&before) != oid {
                    return Err(InputFailure::Unsafe);
                }
                result.materials.push(budget.material(
                    scope,
                    path.clone(),
                    IntentMaterialVersion::Before,
                    &before,
                )?);
            }
            if let Some((_, bytes)) = &current {
                result.materials.push(budget.material(
                    scope,
                    path.clone(),
                    IntentMaterialVersion::Current,
                    bytes,
                )?);
            }
        }
        observations.push((path, current.map(|(stat, _)| stat)));
    }
    Ok(observations)
}

fn repository(path: &Path, budget: &Budget) -> Result<(PathBuf, File, File), InputFailure> {
    let mut path = absolute(path)?;
    loop {
        budget.check()?;
        let root = open_path(&path).map_err(|_| InputFailure::Unsafe)?;
        if !root.metadata().map_err(|_| InputFailure::Unsafe)?.is_dir() {
            return Err(InputFailure::Unsafe);
        }
        match open_child(&root, Path::new(".git")) {
            Ok(git) => {
                if !git.metadata().map_err(|_| InputFailure::Unsafe)?.is_dir() {
                    return Err(InputFailure::Clarification(UNSUPPORTED));
                }
                return Ok((path, root, git));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(InputFailure::Unsafe),
        }
        if !path.pop() {
            return Err(InputFailure::Clarification(
                "Workspace is not a Git worktree; use --attach for explicit files or directories",
            ));
        }
    }
}

fn metadata_bytes(
    dir: &File,
    path: &str,
    limit: usize,
    budget: &mut Budget,
) -> Result<Option<Vec<u8>>, InputFailure> {
    match open_child(dir, Path::new(path)) {
        Ok(mut file) => read_file(&mut file, limit, budget).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(InputFailure::Unsafe),
    }
}

fn head(dir: &File, budget: &mut Budget) -> Result<String, InputFailure> {
    let bytes = metadata_bytes(dir, "HEAD", 4096, budget)?.ok_or(InputFailure::Clarification(
        "Git has no HEAD; create a baseline or supply --attach",
    ))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| InputFailure::Unsafe)?
        .trim();
    if object_id(text) {
        return Ok(text.into());
    }
    let reference = text
        .strip_prefix("ref: refs/heads/")
        .ok_or(InputFailure::Clarification(UNSUPPORTED))?;
    valid_relative(reference)?;
    let reference = format!("refs/heads/{reference}");
    if let Some(bytes) = metadata_bytes(dir, &reference, 4096, budget)? {
        let oid = std::str::from_utf8(&bytes)
            .map_err(|_| InputFailure::Unsafe)?
            .trim();
        return if object_id(oid) {
            Ok(oid.into())
        } else {
            Err(InputFailure::Unsafe)
        };
    }
    let packed = metadata_bytes(dir, "packed-refs", LIST_BYTES, budget)?.unwrap_or_default();
    let packed = std::str::from_utf8(&packed).map_err(|_| InputFailure::Unsafe)?;
    for line in packed.lines().take(RECORDS + 1) {
        if let Some((oid, name)) = line.split_once(' ')
            && name == reference
            && object_id(oid)
        {
            return Ok(oid.into());
        }
    }
    Err(InputFailure::Clarification(
        "Git has no committed HEAD; provide a baseline or --attach",
    ))
}

fn object_id(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn blob_id(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut digest = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    digest.update(format!("blob {}\0", bytes.len()).as_bytes());
    digest.update(bytes);
    digest
        .finish()
        .as_ref()
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

fn file_mode(value: &str) -> Result<u32, InputFailure> {
    match value {
        "100644" => Ok(0o100_644),
        "100755" => Ok(0o100_755),
        _ => Err(InputFailure::Clarification(UNSUPPORTED)),
    }
}

fn records(bytes: &[u8]) -> Result<Vec<&str>, InputFailure> {
    if bytes.is_empty() {
        return Ok(vec![]);
    }
    if bytes.last() != Some(&0) {
        return Err(InputFailure::Unsafe);
    }
    let records: Vec<_> = bytes[..bytes.len() - 1]
        .split(|byte| *byte == 0)
        .map(|line| std::str::from_utf8(line).map_err(|_| InputFailure::Unsafe))
        .collect::<Result<_, _>>()?;
    if records.len() > RECORDS {
        return Err(InputFailure::Limit);
    }
    Ok(records)
}

fn validate_index(bytes: &[u8]) -> Result<(), InputFailure> {
    if bytes.is_empty() {
        return Ok(());
    }
    if bytes.len() < 32 || &bytes[..4] != b"DIRC" {
        return Err(InputFailure::Unsafe);
    }
    let word = |start| {
        bytes
            .get(start..start + 4)
            .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
            .map(u32::from_be_bytes)
            .ok_or(InputFailure::Unsafe)
    };
    if !matches!(word(4)?, 2 | 3) {
        return Err(InputFailure::Clarification(UNSUPPORTED));
    }
    let count = word(8)? as usize;
    if count > RECORDS {
        return Err(InputFailure::Limit);
    }
    let end = bytes.len() - 20;
    if ring::digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, &bytes[..end]).as_ref() != &bytes[end..] {
        return Err(InputFailure::Unsafe);
    }
    let mut offset = 12;
    for _ in 0..count {
        let start = offset;
        let flags = bytes
            .get(offset + 60..offset + 62)
            .ok_or(InputFailure::Unsafe)?;
        if flags[0] & 0x40 != 0 {
            return Err(InputFailure::Clarification(UNSUPPORTED));
        }
        offset += 62;
        let length = bytes
            .get(offset..end)
            .and_then(|tail| tail.iter().position(|byte| *byte == 0))
            .ok_or(InputFailure::Unsafe)?;
        let encoded_length = usize::from(u16::from_be_bytes([flags[0], flags[1]]) & 0x0fff);
        if length == 0 || length > 4096 || encoded_length != length.min(0x0fff) {
            return Err(InputFailure::Unsafe);
        }
        offset = start + (62 + length + 1).div_ceil(8) * 8;
        if offset > end
            || bytes[start + 62 + length..offset]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Err(InputFailure::Unsafe);
        }
    }
    while offset < end {
        let signature = bytes.get(offset..offset + 4).ok_or(InputFailure::Unsafe)?;
        let length = word(offset + 4)? as usize;
        if !signature[0].is_ascii_uppercase() {
            return Err(InputFailure::Clarification(UNSUPPORTED));
        }
        offset = offset.checked_add(8 + length).ok_or(InputFailure::Unsafe)?;
        if offset > end {
            return Err(InputFailure::Unsafe);
        }
    }
    Ok(())
}

fn copy_objects(dir: &File, destination: &Path, budget: &mut Budget) -> Result<(), InputFailure> {
    let objects = open_child(dir, Path::new("objects")).map_err(|_| InputFailure::Unsafe)?;
    let mut count = 0;
    for entry in Dir::read_from(&objects).map_err(|_| InputFailure::Unsafe)? {
        budget.check()?;
        let entry = entry.map_err(|_| InputFailure::Unsafe)?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| InputFailure::Unsafe)?;
        if matches!(name, "." | "..") {
            continue;
        }
        count += 1;
        if count > RECORDS {
            return Err(InputFailure::Limit);
        }
        valid_relative(name)?;
        let target = destination.join(name);
        let sub = open_child(&objects, Path::new(name)).map_err(|_| InputFailure::Unsafe)?;
        if !sub.metadata().map_err(|_| InputFailure::Unsafe)?.is_dir() {
            return Err(InputFailure::Unsafe);
        }
        fs::create_dir(&target).map_err(|_| InputFailure::Unsafe)?;
        for child in Dir::read_from(&sub).map_err(|_| InputFailure::Unsafe)? {
            budget.check()?;
            count += 1;
            if count > RECORDS {
                return Err(InputFailure::Limit);
            }
            let child = child.map_err(|_| InputFailure::Unsafe)?;
            let name = child
                .file_name()
                .to_str()
                .map_err(|_| InputFailure::Unsafe)?;
            if matches!(name, "." | "..") {
                continue;
            }
            if name.ends_with(".promisor") || matches!(name, "alternates" | "http-alternates") {
                return Err(InputFailure::Clarification(UNSUPPORTED));
            }
            valid_relative(name)?;
            let mut file = open_child(&sub, Path::new(name)).map_err(|_| InputFailure::Unsafe)?;
            let bytes = read_file(&mut file, 64 * 1024 * 1024, budget)?;
            fs::write(target.join(name), bytes).map_err(|_| InputFailure::Unsafe)?;
        }
    }
    Ok(())
}

struct Git<'a> {
    metadata: &'a Path,
}
impl Git<'_> {
    fn run(&self, args: &[&str], limit: usize, budget: &Budget) -> Result<Vec<u8>, InputFailure> {
        budget.check()?;
        let mut child = Command::new("/usr/bin/git")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ALLOW_PROTOCOL", "")
            .arg("--no-pager")
            .arg("--git-dir")
            .arg(self.metadata)
            .args(args)
            .current_dir(self.metadata)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| InputFailure::Clarification(UNSUPPORTED))?;
        let stdout = child.stdout.take().ok_or(InputFailure::Unsafe)?;
        let stderr = child.stderr.take().ok_or(InputFailure::Unsafe)?;
        let out = thread::spawn(move || bounded_read(stdout, limit));
        let err = thread::spawn(move || bounded_read(stderr, 4096));
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if std::time::Instant::now() < budget.deadline() => {
                    thread::sleep(Duration::from_millis(2));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(InputFailure::Limit);
                }
            }
        };
        let stdout = out.join().map_err(|_| InputFailure::Unsafe)?;
        let stderr = err.join().map_err(|_| InputFailure::Unsafe)?;
        let status = status?;
        let stdout = stdout.map_err(|_| InputFailure::Limit)?;
        stderr.map_err(|_| InputFailure::Limit)?;
        budget.check()?;
        if !status.success() {
            return Err(InputFailure::Clarification(UNSUPPORTED));
        }
        Ok(stdout)
    }
}

fn bounded_read(reader: impl io::Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::other("git output exceeds budget"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(version: u32, count: u32, body: &[u8]) -> Vec<u8> {
        let mut bytes = b"DIRC".to_vec();
        bytes.extend(version.to_be_bytes());
        bytes.extend(count.to_be_bytes());
        bytes.extend(body);
        let hash = ring::digest::digest(&SHA1_FOR_LEGACY_USE_ONLY, &bytes);
        bytes.extend(hash.as_ref());
        bytes
    }

    #[test]
    fn index_requires_supported_complete_checksummed_entries() {
        assert!(validate_index(&[]).is_ok());
        assert!(validate_index(&index(2, 0, &[])).is_ok());
        let mut entry = vec![0; 64];
        entry[61] = 1;
        entry[62] = b'a';
        assert!(validate_index(&index(2, 1, &entry)).is_ok());
        for version in [0, 1, 4, u32::MAX] {
            assert!(validate_index(&index(version, 0, &[])).is_err());
        }
        assert!(validate_index(&index(2, 65_537, &[])).is_err());
        assert!(validate_index(&index(2, 1, &[])).is_err());
        for flag in [0x40, 0x60] {
            entry[60] = flag;
            assert!(validate_index(&index(3, 1, &entry)).is_err());
        }
        entry[60] = 0;
        entry[61] = 2;
        assert!(validate_index(&index(2, 1, &entry)).is_err());
        assert!(validate_index(&index(2, 0, b"link\0\0\0\0")).is_err());
        assert!(validate_index(&index(2, 0, b"TREE\0\0\0\x10")).is_err());
        let mut corrupted = index(2, 0, &[]);
        corrupted[12] ^= 1;
        assert!(validate_index(&corrupted).is_err());
        for end in 1..corrupted.len() {
            assert!(validate_index(&corrupted[..end]).is_err());
        }
    }

    #[test]
    fn git_output_records_and_bytes_are_bounded() {
        assert_eq!(records(b"a\0b\0").unwrap(), ["a", "b"]);
        for bytes in [b"a".as_slice(), b"\xff\0"] {
            assert!(records(bytes).is_err());
        }
        assert!(records(&b"a\0".repeat(RECORDS + 1)).is_err());
        assert_eq!(bounded_read(b"abc".as_slice(), 3).unwrap(), b"abc");
        assert!(bounded_read(b"abcd".as_slice(), 3).is_err());
        assert!(!object_id("--help"));
        assert!(!object_id(&"f".repeat(41)));
        assert!(file_mode("120000").is_err());
    }
}
