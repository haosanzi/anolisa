//! Deterministic file roles of the archive commands a command model keeps missing.
//!
//! `tar -czf out.tgz -C src .` creates `out.tgz` and reads `src`, but both happen inside the
//! program, so a model reading the command line can state neither: probing the same command twice
//! produced one answer without any file right and one that named the output, not its directory.
//! The option grammar is fixed, so the roles are read here instead and
//! [`crate::propose_command`] adds what the model left out.
//!
//! Only text that can be read without expanding anything is recognized. A substitution,
//! redirection, pipeline, brace expansion or unknown option turns the whole command into "no
//! roles", so the caller keeps the model text as it is instead of gaining a guessed scope.

use std::fmt::Write as _;

/// Paths one archive command reads and the directories it writes into.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ArchiveRoles {
    /// Canonical absolute paths the command reads; a directory names its whole subtree.
    reads: Vec<String>,
    /// Canonical absolute directories the command creates or overwrites files in.
    writes: Vec<String>,
    /// Canonical absolute archive files the command creates; none of them exists yet.
    archives: Vec<String>,
}

/// Reads the file roles of every archive command in `command`, against `cwd`.
///
/// Returns `None` when the command holds no archive invocation, or when any part of it cannot be
/// read without expanding it; the caller then keeps the model text unchanged.
pub(crate) fn archive_roles(command: &str, cwd: &str) -> Option<ArchiveRoles> {
    let mut roles = ArchiveRoles {
        reads: Vec::new(),
        writes: Vec::new(),
        archives: Vec::new(),
    };
    let mut recognized = false;
    for words in simple_commands(command)? {
        let head = words.first()?;
        if !is_tar(head) {
            continue;
        }
        recognized = true;
        let tar = tar_roles(&words, cwd)?;
        roles.reads.extend(tar.reads);
        roles.writes.extend(tar.writes);
        roles.archives.extend(tar.archives);
    }
    if !recognized {
        return None;
    }
    dedupe(&mut roles.reads);
    dedupe(&mut roles.writes);
    dedupe(&mut roles.archives);
    Some(roles)
}

impl ArchiveRoles {
    /// Renders the roles as Cedar permits that union with a model candidate.
    ///
    /// Each path is written as an equality-then-subtree pair: the sandbox projects a directory
    /// from both halves, and one half alone turns the grant into a point or a descendants-only
    /// scope the execution side refuses.
    pub(crate) fn cedar(&self) -> String {
        let mut out = String::from(
            "// Deterministic archive roles: the archive is created in its directory and the \
             sources are read as directory subtrees.\n",
        );
        for (action, paths) in [("file.read", &self.reads), ("file.write", &self.writes)] {
            if paths.is_empty() {
                continue;
            }
            let clauses = paths
                .iter()
                .map(|path| {
                    let point = cedar_string(path);
                    if path == "/" {
                        format!("resource.path == {point}")
                    } else {
                        format!(
                            "resource.path == {point} || resource.path like {}",
                            cedar_string(&format!("{path}/*"))
                        )
                    }
                })
                .collect::<Vec<_>>()
                .join(" ||\n  ");
            // String's fmt::Write implementation cannot return an error.
            let _ = write!(
                out,
                "permit(\n  principal,\n  action == SecCore::Action::\"{action}\",\n  resource is SecCore::File\n)\nwhen {{\n  {clauses}\n}};\n"
            );
        }
        out
    }

    /// Returns the archive files this command creates.
    ///
    /// None of them exists until the command finishes, so a statement naming one cannot become
    /// part of the permission input and has to go; [`Self::named_caveat`] says so.
    pub(crate) fn archives(&self) -> &[String] {
        &self.archives
    }

    /// Explains the statements dropped because they named an archive the command creates.
    pub(crate) fn named_caveat(&self, dropped: usize) -> String {
        format!(
            "deterministic archive roles: dropped {dropped} rule(s) naming the archive ({}) itself, \
             which exists only after the command writes it, so the directory write creates it",
            self.archives.join(", ")
        )
    }

    /// Describes what the roles add and why the write is a directory, not the archive file.
    pub(crate) fn caveat(&self) -> String {
        let mut caveat = String::from(
            "deterministic archive roles: the archive creates a new file, so write is granted on \
             the directory that holds it",
        );
        if !self.writes.is_empty() {
            // String's fmt::Write implementation cannot return an error.
            let _ = write!(caveat, " ({})", self.writes.join(", "));
        }
        if !self.reads.is_empty() {
            let _ = write!(
                caveat,
                "; the sources are read as directory pairs ({})",
                self.reads.join(", ")
            );
        }
        caveat
    }
}

/// One shell command line split into simple commands of unquoted words.
///
/// Quoting is undone and comments are dropped, because the option grammar is read on plain words.
/// Anything whose expansion would change the words — command or parameter substitution, backticks,
/// subshells and redirections — makes the whole line unreadable.
fn simple_commands(command: &str) -> Option<Vec<Vec<String>>> {
    let mut commands = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;
    let mut chars = command.chars().peekable();
    while let Some(ch) = chars.next() {
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                } else {
                    word.push(ch);
                }
            }
            Some(_) => match ch {
                '"' => quote = None,
                // The shell only removes a backslash before these characters inside quotes.
                '\\' => match chars.next()? {
                    escaped @ ('"' | '\\' | '$' | '`') => word.push(escaped),
                    _ => return None,
                },
                '$' | '`' => return None,
                other => word.push(other),
            },
            None => match ch {
                '\'' | '"' => {
                    quote = Some(ch);
                    started = true;
                }
                '\\' => {
                    if chars.next()? != '\n' {
                        return None;
                    }
                }
                ' ' | '\t' => {
                    if started {
                        words.push(std::mem::take(&mut word));
                        started = false;
                    }
                }
                ';' | '|' | '&' | '\n' => {
                    if started {
                        words.push(std::mem::take(&mut word));
                        started = false;
                    }
                    if !words.is_empty() {
                        commands.push(std::mem::take(&mut words));
                    }
                }
                '#' if !started => {
                    for next in chars.by_ref() {
                        if next == '\n' {
                            break;
                        }
                    }
                }
                '$' | '`' | '(' | ')' | '<' | '>' => return None,
                other => {
                    word.push(other);
                    started = true;
                }
            },
        }
    }
    if quote.is_some() {
        return None;
    }
    if started {
        words.push(word);
    }
    if !words.is_empty() {
        commands.push(words);
    }
    Some(commands)
}

/// Whether a command word names tar, by bare name or by an absolute path.
fn is_tar(word: &str) -> bool {
    matches!(word.rsplit('/').next(), Some("tar" | "gtar"))
}

/// Long options that take a value this analysis only skips: they narrow or label the archive.
const LONG_VALUE_OPTIONS: &[&str] = &[
    "exclude",
    "exclude-from",
    "exclude-tag",
    "exclude-tag-all",
    "exclude-tag-under",
    "after-date",
    "newer",
    "warning",
    "format",
    "owner",
    "group",
    "mode",
    "transform",
    "use-compress-program",
    "label",
    "tape-length",
    "blocking-factor",
    "listed-incremental",
    "starting-file",
    "info-script",
    "new-volume-script",
    "checkpoint-action",
    "occurrence",
    "level",
    "index-file",
    "hole-detection",
    "sort",
    "quote-chars",
    "mtime",
];

/// Long options that name no path; they only change the archive format or the output verbosity.
const LONG_FLAGS: &[&str] = &[
    "verbose",
    "gzip",
    "gunzip",
    "ungzip",
    "bzip2",
    "xz",
    "lzip",
    "lzma",
    "lzop",
    "zstd",
    "compress",
    "uncompress",
    "auto-compress",
    "no-auto-compress",
    "posix",
    "sparse",
    "one-file-system",
    "numeric-owner",
    "no-same-owner",
    "same-owner",
    "no-same-permissions",
    "same-permissions",
    "preserve-permissions",
    "preserve-order",
    "same-order",
    "ignore-failed-read",
    "ignore-zeros",
    "no-recursion",
    "recursion",
    "wildcards",
    "no-wildcards",
    "anchored",
    "no-anchored",
    "ignore-case",
    "no-ignore-case",
    "dereference",
    "hard-dereference",
    "atime-preserve",
    "check-links",
    "totals",
    "checkpoint",
    "show-transformed-names",
    "show-omitted-dirs",
    "block-number",
    "full-time",
    "restrict",
    "utc",
    "no-unquote",
    "unquote",
    "verbatim-files-from",
    "no-verbatim-files-from",
    "seek",
    "no-seek",
    "show-defaults",
    "xattrs",
    "no-xattrs",
    "acls",
    "no-acls",
    "selinux",
    "no-selinux",
    "backup",
    "remove-files",
    "keep-old-files",
    "skip-old-files",
    "overwrite-dir",
    "no-overwrite-dir",
    "absolute-names",
    "no-absolute-names",
    "show-stored-names",
    "old-archive",
    "portability",
    "read-full-records",
    "pax-option",
    "delay-directory-restore",
    "no-delay-directory-restore",
];

/// Long options whose roles differ from creating: they read an existing archive or take the
/// sources from somewhere this analysis does not read.
const LONG_OTHER_MODES: &[&str] = &[
    "extract",
    "get",
    "list",
    "append",
    "update",
    "delete",
    "compare",
    "diff",
    "concatenate",
    "catenate",
    "files-from",
];

/// Short options that take a value; a cluster such as `-czf` carries it in the letters after the
/// flag or in the following word.
const SHORT_VALUE_OPTIONS: &[char] = &[
    'b', 'C', 'F', 'f', 'g', 'H', 'I', 'K', 'L', 'N', 'T', 'V', 'X',
];

/// Short options whose roles differ from creating.
const SHORT_OTHER_MODES: &[char] = &['A', 'd', 'r', 't', 'u', 'x'];

/// The roles a tar invocation states, plus the option state the parse walks through.
struct TarOptions {
    create: bool,
    archive: Option<String>,
    base: String,
    sources: Vec<String>,
}

/// Reads the roles of one tar invocation.
///
/// Only creating invocations are recognized: extracting and listing have different roles, and the
/// model is left alone for them. An option whose name or arity is unknown also yields `None`, since
/// the value it may take would shift every operand after it.
fn tar_roles(words: &[String], cwd: &str) -> Option<ArchiveRoles> {
    let mut options = TarOptions {
        create: false,
        archive: None,
        base: cwd.to_owned(),
        sources: Vec::new(),
    };
    let mut operands_only = false;
    let mut index = 1;
    while index < words.len() {
        let word = words[index].as_str();
        if operands_only || word == "-" || !word.starts_with('-') {
            if word == "-" {
                return None;
            }
            options.sources.push(source_path(&options.base, word)?);
        } else if word == "--" {
            operands_only = true;
        } else if let Some(option) = word.strip_prefix("--") {
            parse_long(&mut options, option, words, &mut index)?;
        } else {
            parse_short(&mut options, word, words, &mut index)?;
        }
        index += 1;
    }
    if !options.create {
        return None;
    }
    let archive = options.archive?;
    let mut writes = Vec::new();
    let mut archives = Vec::new();
    // `-f -` writes the archive to stdout; no file is created. Without `-f` tar uses a default
    // device that this analysis cannot know, so it yields nothing.
    if archive != "-" {
        let path = resolve(cwd, &archive)?;
        writes.push(parent_directory(&path)?);
        archives.push(path);
    }
    Some(ArchiveRoles {
        reads: options.sources,
        writes,
        archives,
    })
}

/// Reads one `--name` or `--name=value` word into the option state.
fn parse_long(
    options: &mut TarOptions,
    option: &str,
    words: &[String],
    index: &mut usize,
) -> Option<()> {
    let (name, attached) = option
        .split_once('=')
        .map_or((option, None), |(name, value)| (name, Some(value)));
    if name == "create" {
        flag(attached)?;
        options.create = true;
    } else if name == "file" {
        options.archive = Some(option_value(attached, words, index)?);
    } else if name == "directory" {
        options.base = resolve(&options.base, &option_value(attached, words, index)?)?;
    } else if LONG_OTHER_MODES.contains(&name) {
        return None;
    } else if LONG_VALUE_OPTIONS.contains(&name) {
        option_value(attached, words, index)?;
    } else if LONG_FLAGS.contains(&name) {
        flag(attached)?;
    } else {
        // An unknown name cannot be told from one that consumes the next word.
        return None;
    }
    Some(())
}

/// Reads one short cluster such as `-czf` into the option state.
fn parse_short(
    options: &mut TarOptions,
    word: &str,
    words: &[String],
    index: &mut usize,
) -> Option<()> {
    let letters: Vec<char> = word.chars().skip(1).collect();
    let mut position = 0;
    while position < letters.len() {
        let flag = letters[position];
        if flag == 'c' {
            options.create = true;
            position += 1;
        } else if SHORT_OTHER_MODES.contains(&flag) {
            return None;
        } else if SHORT_VALUE_OPTIONS.contains(&flag) {
            let attached: Option<String> =
                (position + 1 < letters.len()).then(|| letters[position + 1..].iter().collect());
            let value = option_value(attached.as_deref(), words, index)?;
            match flag {
                'f' => options.archive = Some(value),
                'C' => options.base = resolve(&options.base, &value)?,
                'T' => return None,
                _ => {}
            }
            return Some(());
        } else {
            position += 1;
        }
    }
    Some(())
}

/// Rejects a value attached to an option that takes none.
fn flag(attached: Option<&str>) -> Option<()> {
    attached.is_none().then_some(())
}

/// Returns the option value: attached after `=` or in the cluster, otherwise the next word.
fn option_value(attached: Option<&str>, words: &[String], index: &mut usize) -> Option<String> {
    if let Some(value) = attached {
        return Some(value.to_owned());
    }
    *index += 1;
    words.get(*index).cloned()
}

/// Resolves one archive source, treating a glob as the directory it is expanded in.
fn source_path(base: &str, operand: &str) -> Option<String> {
    // Brace expansion names several paths this analysis cannot enumerate; the caller keeps the
    // model text instead.
    if operand.contains(['{', '}']) {
        return None;
    }
    if operand.contains(['*', '?', '[']) {
        return Some(base.to_owned());
    }
    resolve(base, operand)
}

/// Resolves a literal operand against `base` into a canonical absolute path.
///
/// Only lexical work happens here: no path metadata is read. `..` is folded lexically, which is
/// the same object unless an earlier component is a link; a path that names no object is rejected
/// later when the permission input resolves its literals.
fn resolve(base: &str, value: &str) -> Option<String> {
    // Tilde expansion depends on the environment, so a leading `~` is not a path literal.
    if value.is_empty() || value.starts_with('~') || value.contains('\\') {
        return None;
    }
    let joined = if value.starts_with('/') {
        value.to_owned()
    } else {
        format!("{base}/{value}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => {
                if other
                    .chars()
                    .any(|ch| ch.is_control() || matches!(ch, '*' | '?' | '[' | '{'))
                {
                    return None;
                }
                parts.push(other);
            }
        }
    }
    Some(if parts.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", parts.join("/"))
    })
}

/// Returns the directory that holds `path`; the archive is created inside it.
fn parent_directory(path: &str) -> Option<String> {
    let cut = path.rfind('/')?;
    Some(if cut == 0 {
        "/".to_owned()
    } else {
        path[..cut].to_owned()
    })
}

fn cedar_string(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\\\""))
}

fn dedupe(paths: &mut Vec<String>) {
    let mut index = 0;
    while index < paths.len() {
        if paths[..index].contains(&paths[index]) {
            paths.remove(index);
        } else {
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles(command: &str) -> (Vec<String>, Vec<String>) {
        let roles = archive_roles(command, "/work").expect("roles");
        (roles.reads, roles.writes)
    }

    fn paths(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn a_create_command_writes_the_archive_directory_and_reads_its_sources() {
        assert_eq!(
            roles("tar -czf /work/out.tgz -C /work/repo ."),
            (paths(&["/work/repo"]), paths(&["/work"]))
        );
    }

    #[test]
    fn long_options_name_the_same_roles() {
        assert_eq!(
            roles("tar --create --file=/work/out.tgz --directory=/work/repo --verbose ."),
            (paths(&["/work/repo"]), paths(&["/work"]))
        );
        assert_eq!(
            roles("tar --create --file /work/out.tgz --directory /work/repo ."),
            (paths(&["/work/repo"]), paths(&["/work"]))
        );
    }

    #[test]
    fn the_archive_stays_relative_to_the_launch_directory_after_c() {
        assert_eq!(
            roles("tar -czf out.tgz -C repo ."),
            (paths(&["/work/repo"]), paths(&["/work"]))
        );
    }

    #[test]
    fn several_c_options_accumulate_like_tar_does() {
        assert_eq!(
            roles("tar -czf /work/out.tgz -C a b -C c f2"),
            (paths(&["/work/a/b", "/work/a/c/f2"]), paths(&["/work"]))
        );
    }

    #[test]
    fn bare_operands_and_a_glob_read_from_the_launch_directory() {
        assert_eq!(
            roles("tar -czf out.tgz one.txt *.log"),
            (paths(&["/work/one.txt", "/work"]), paths(&["/work"]))
        );
    }

    #[test]
    fn a_created_archive_names_the_file_that_does_not_exist_yet() {
        let roles = archive_roles("tar -czf out.tgz -C repo .", "/work").unwrap();
        assert_eq!(roles.archives, paths(&["/work/out.tgz"]));
        // The archive stays next to the launch directory even when `-C` moves the sources.
        assert_eq!(roles.writes, paths(&["/work"]));
        let stdout = archive_roles("tar -czf - -C repo .", "/work").unwrap();
        assert!(stdout.archives.is_empty(), "{stdout:?}");
    }

    #[test]
    fn a_stdout_archive_creates_no_file() {
        assert_eq!(
            roles("tar -czf - -C repo ."),
            (paths(&["/work/repo"]), vec![])
        );
    }

    #[test]
    fn several_tar_commands_union_their_roles() {
        assert_eq!(
            roles("tar -czf a.tgz -C one . && tar -czf b.tgz -C two ."),
            (paths(&["/work/one", "/work/two"]), paths(&["/work"]))
        );
    }

    #[test]
    fn other_commands_yield_no_roles() {
        assert!(archive_roles("cat a.txt > b.txt", "/work").is_none());
        assert!(archive_roles("/usr/bin/tar", "/work").is_none());
    }

    #[test]
    fn extracting_and_listing_yield_no_roles() {
        for command in ["tar -xzf out.tgz", "tar -tzf out.tgz", "tar -rf out.tgz x"] {
            assert!(archive_roles(command, "/work").is_none(), "{command}");
        }
    }

    #[test]
    fn unreadable_command_text_yields_no_roles() {
        for command in [
            "tar -czf out.tgz -C $DIR .",
            "tar -czf out.tgz $(pwd)",
            "tar -czf out.tgz . 2>/dev/null",
            "tar -czf out.tgz {a,b}",
            "tar -czf out.tgz ~/data",
            "tar -czf out.tgz -T list.txt",
            "tar -czf out.tgz --unknown-option x",
            "tar -czf",
        ] {
            assert!(archive_roles(command, "/work").is_none(), "{command}");
        }
    }

    #[test]
    fn rendered_cedar_pairs_every_path_and_validates() {
        let roles = archive_roles("tar -czf /work/out.tgz -C /work/repo .", "/work").unwrap();
        let text = roles.cedar();
        assert!(
            text.contains("resource.path == \"/work/repo\" || resource.path like \"/work/repo/*\"")
        );
        assert!(text.contains("resource.path == \"/work\" || resource.path like \"/work/*\""));
        crate::prepare_policy(&text).expect("validated");
    }
}
