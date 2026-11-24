//! Parse the static filesystem subset of Island's Landlock Config TOML.

use landlock::{ABI, Access as _, AccessFs, BitFlags};
use serde::Deserialize;

use crate::{LandlockError, MAX_PATHS, invalid, validate_path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    abi: Option<i32>,
    #[serde(default)]
    ruleset: Vec<Ruleset>,
    #[serde(default)]
    path_beneath: Vec<PathBeneath>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ruleset {
    handled_access_fs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathBeneath {
    parent: Vec<String>,
    allowed_access: Vec<String>,
}

pub(super) struct FilesystemPolicy {
    pub handled: BitFlags<AccessFs>,
    pub grants: Vec<(String, BitFlags<AccessFs>)>,
}

pub(super) fn compile(text: &str) -> Result<FilesystemPolicy, LandlockError> {
    let policy: Policy = toml::from_str(text)?;
    let abi = policy
        .abi
        .map(|version| match version {
            1..=6 => Ok(ABI::from(version)),
            _ => Err(invalid(format!("unsupported Island policy ABI: {version}"))),
        })
        .transpose()?;

    let mut handled = BitFlags::empty();
    for ruleset in policy.ruleset {
        handled |= access_mask(&ruleset.handled_access_fs, abi)?;
    }
    let mut grants = Vec::new();
    for rule in policy.path_beneath {
        if rule.parent.is_empty() {
            return Err(invalid("Island path_beneath requires at least one parent"));
        }
        if grants.len() + rule.parent.len() > MAX_PATHS {
            return Err(invalid("too many Landlock policy paths"));
        }
        let access = access_mask(&rule.allowed_access, abi)?;
        // Island also handles rights used by an allowance even if its
        // ruleset table does not name them.
        handled |= access;
        for parent in rule.parent {
            validate_path(&parent)?;
            grants.push((parent, access));
        }
    }
    if handled.is_empty() {
        return Err(invalid("Island policy handles no filesystem access"));
    }
    Ok(FilesystemPolicy { handled, grants })
}

fn access_mask(values: &[String], abi: Option<ABI>) -> Result<BitFlags<AccessFs>, LandlockError> {
    if values.is_empty() {
        return Err(invalid("Island filesystem access list is empty"));
    }
    let mut mask = BitFlags::empty();
    for value in values {
        let access = match value.as_str() {
            "abi.all" | "abi.read_execute" | "abi.read_write" => {
                let abi = abi.ok_or_else(|| invalid(format!("{value} requires a policy ABI")))?;
                let all = AccessFs::from_all(abi);
                match value.as_str() {
                    // Island includes Refer in its read-and-execute group.
                    "abi.read_execute" => AccessFs::from_read(abi) | (all & AccessFs::Refer),
                    "abi.read_write" => all & !AccessFs::Execute,
                    _ => all,
                }
            }
            "execute" => AccessFs::Execute.into(),
            "write_file" => AccessFs::WriteFile.into(),
            "read_file" => AccessFs::ReadFile.into(),
            "read_dir" => AccessFs::ReadDir.into(),
            "remove_dir" => AccessFs::RemoveDir.into(),
            "remove_file" => AccessFs::RemoveFile.into(),
            "make_char" => AccessFs::MakeChar.into(),
            "make_dir" => AccessFs::MakeDir.into(),
            "make_reg" => AccessFs::MakeReg.into(),
            "make_sock" => AccessFs::MakeSock.into(),
            "make_fifo" => AccessFs::MakeFifo.into(),
            "make_block" => AccessFs::MakeBlock.into(),
            "make_sym" => AccessFs::MakeSym.into(),
            "refer" => AccessFs::Refer.into(),
            "truncate" => AccessFs::Truncate.into(),
            "ioctl_dev" => AccessFs::IoctlDev.into(),
            _ => {
                return Err(invalid(format!(
                    "unsupported Island filesystem access: {value}"
                )));
            }
        };
        mask |= access;
    }
    Ok(mask)
}
