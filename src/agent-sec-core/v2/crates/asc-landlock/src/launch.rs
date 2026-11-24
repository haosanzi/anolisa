//! Launch a program with a static Landlock file access policy.

use std::convert::Infallible;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, IsTerminal as _, Read as _};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Command;

use asc_policy_types::authoring::PolicySource;
use asc_policy_types::cedar::CedarPolicySource;
use landlock::{
    ABI, AccessFs, BitFlags, CompatLevel, Compatible as _, PathBeneath, Ruleset, RulesetAttr as _,
    RulesetCreated, RulesetCreatedAttr as _, RulesetStatus,
};
use rustix::fs::{self, FileType, Mode, OFlags, ResolveFlags};

use crate::{LandlockError, invalid, island, policy};

const MAX_POLICY_BYTES: u64 = 4 * 1024 * 1024;

/// Install a file access policy and replace the current process with the target.
///
/// The input accepts Cedar text, a Cedar source envelope, or an Island
/// filesystem policy with a `.toml` extension.
///
/// # Errors
/// Rejects unsupported policies, invalid grant paths and incomplete
/// kernel enforcement. If the final exec fails, the calling thread remains
/// restricted and should exit.
pub fn exec(policy_path: &Path, command: &mut Command) -> Result<Infallible, LandlockError> {
    let text = read_policy(policy_path)?;
    if policy_path.extension() == Some(OsStr::new("toml")) {
        install_island(&text)?;
    } else {
        install(&cedar_source(text)?)?;
    }
    Err(command.exec().into())
}

fn install_island(text: &str) -> Result<(), LandlockError> {
    let policy = island::compile(text)?;
    let mut rules = strict_ruleset(policy.handled)?;
    for (path, access) in policy.grants {
        let (descriptor, kind) = open_grant(&path)?;
        let null_access = AccessFs::ReadFile | AccessFs::WriteFile;
        if kind == FileType::CharacterDevice && !null_access.contains(access) {
            return Err(invalid(
                "only read_file and write_file are supported on /dev/null",
            ));
        }
        rules = rules
            .add_rule(PathBeneath::new(descriptor, access))
            .map_err(kernel_error)?;
    }
    enforce(rules)
}

/// Installs a policy snapshot for the current launcher and its future children.
///
/// # Errors
/// Rejects invalid launch I/O, unsupported policies and incomplete enforcement.
/// Callers must exit if a post-install launch fails.
pub fn install(source: &CedarPolicySource) -> Result<(), LandlockError> {
    let grants = policy::compile(source)?;

    let read = AccessFs::ReadFile | AccessFs::ReadDir;
    let write = AccessFs::from_write(ABI::V3);
    let mut rules = strict_ruleset(read | write)?;

    for (scope, rights) in grants {
        let (descriptor, kind) = open_grant(&scope.path)?;
        let (read_flags, write_flags) = match (scope.tree, kind) {
            (true, FileType::Directory) => (read, write),
            (false, FileType::RegularFile) => (
                AccessFs::ReadFile.into(),
                AccessFs::WriteFile | AccessFs::Truncate,
            ),
            // Cosh opens null streams for its startup workers.
            // An exact grant avoids granting the whole host device directory.
            (false, FileType::CharacterDevice) if scope.path == "/dev/null" => {
                (AccessFs::ReadFile.into(), AccessFs::WriteFile.into())
            }
            _ => return Err(invalid(format!("unexpected object type: {}", scope.path))),
        };
        let access = match (rights.read, rights.write) {
            (true, true) => read_flags | write_flags,
            (true, false) => read_flags,
            (false, true) => write_flags,
            (false, false) => return Err(invalid("empty Landlock path grant")),
        };
        rules = rules
            .add_rule(PathBeneath::new(descriptor, access))
            .map_err(kernel_error)?;
    }
    enforce(rules)
}

fn strict_ruleset(access: BitFlags<AccessFs>) -> Result<RulesetCreated, LandlockError> {
    Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(access)
        .map_err(kernel_error)?
        .create()
        .map_err(kernel_error)
}

fn enforce(rules: RulesetCreated) -> Result<(), LandlockError> {
    validate_stdio(io::stdin().as_fd(), io::stdin().is_terminal())?;
    validate_stdio(io::stdout().as_fd(), io::stdout().is_terminal())?;
    validate_stdio(io::stderr().as_fd(), io::stderr().is_terminal())?;
    // Pre-opened file descriptions keep their original access. Mark
    // inherited non-stdio descriptors before executing the target program.
    close_fds::set_fds_cloexec(3, &[]);
    let status = rules.restrict_self().map_err(kernel_error)?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(kernel_error("partial Landlock ruleset"));
    }
    Ok(())
}

fn read_policy(path: &Path) -> Result<String, LandlockError> {
    let mut text = String::new();
    let size = File::open(path)?
        .take(MAX_POLICY_BYTES + 1)
        .read_to_string(&mut text)?;
    if u64::try_from(size).unwrap_or(u64::MAX) > MAX_POLICY_BYTES {
        return Err(invalid("the policy file exceeds 4 MiB"));
    }
    Ok(text)
}

fn cedar_source(text: String) -> Result<CedarPolicySource, LandlockError> {
    if text.trim_start().starts_with('{') {
        match serde_json::from_str(&text)? {
            PolicySource::Cedar(source) => return Ok(source),
            PolicySource::SecCore(_) => return Err(invalid("expected a Cedar policy envelope")),
        }
    }
    Ok(CedarPolicySource {
        schema: asc_policy_cedar::schema::embedded_reference(),
        text,
    })
}

fn open_grant(path: &str) -> Result<(OwnedFd, FileType), LandlockError> {
    let descriptor = fs::openat2(
        fs::CWD,
        path,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|error| invalid(format!("cannot pin Landlock path {path}: {error}")))?;
    let stat = fs::fstat(&descriptor)?;
    let kind = FileType::from_raw_mode(stat.st_mode);
    match kind {
        FileType::Directory | FileType::RegularFile => {}
        FileType::CharacterDevice if path == "/dev/null" => {}
        _ => return Err(invalid(format!("unexpected object type: {path}"))),
    }
    if kind != FileType::Directory && stat.st_nlink != 1 {
        return Err(invalid(format!("multiply linked file grant: {path}")));
    }
    Ok((descriptor, kind))
}

fn validate_stdio(fd: impl AsFd, terminal: bool) -> Result<(), LandlockError> {
    let stat = fs::fstat(fd)?;
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Fifo | FileType::Socket => return Ok(()),
        FileType::CharacterDevice => {
            let null = fs::stat("/dev/null")?;
            if terminal || (stat.st_dev, stat.st_ino) == (null.st_dev, null.st_ino) {
                return Ok(());
            }
        }
        _ => {}
    }
    Err(invalid(
        "standard I/O must use a terminal, /dev/null, pipe, or socket",
    ))
}

fn kernel_error(message: impl std::fmt::Display) -> LandlockError {
    LandlockError::Kernel(message.to_string())
}
