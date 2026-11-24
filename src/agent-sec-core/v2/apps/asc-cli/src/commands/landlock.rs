//! CLI arguments for launching a program with Landlock.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use asc_daemon_protocol::{DaemonResponse, ResolveLandlockParams, method::LANDLOCK_RESOLVE};
use asc_policy_types::authoring::PolicySource;
use asc_policy_types::scope::PreparedScope;
use clap::Args;

use super::common::encode;

/// Launch parameters for a static file access policy.
#[derive(Debug, Args)]
pub struct LandlockRun {
    /// Cedar file access policy or an Island filesystem policy with a .toml extension.
    #[arg(
        long,
        required_unless_present = "from_scope",
        conflicts_with = "from_scope"
    )]
    policy: Option<PathBuf>,
    /// Look up the policy from the Scope bound to an absolute executable path.
    #[arg(long)]
    from_scope: bool,
    /// Executable name or path, followed by its arguments.
    #[arg(trailing_var_arg = true, required = true, num_args = 1..)]
    command: Vec<OsString>,
}

impl LandlockRun {
    pub(crate) const fn requires_daemon(&self) -> bool {
        self.from_scope
    }

    /// Installs the selected policy and replaces the launcher with the command.
    ///
    /// # Errors
    /// Returns an error if policy lookup, rule installation, or exec fails.
    pub fn run(&self, socket: Option<&Path>, timeout: Duration) -> io::Result<u8> {
        let (program, args) = self
            .command
            .split_first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing command"))?;
        if let Some(policy) = &self.policy {
            return asc_landlock::exec(policy, Command::new(program).args(args))
                .map(|never| match never {})
                .map_err(io::Error::other);
        }
        let socket = socket.ok_or_else(|| io::Error::other("missing daemon endpoint"))?;
        run_from_scope(program, args, socket, timeout)
    }
}

fn run_from_scope(
    program: &OsStr,
    args: &[OsString],
    socket: &Path,
    timeout: Duration,
) -> io::Result<u8> {
    if !Path::new(program).is_absolute() {
        return Err(io::Error::other(
            "the launch executable must be an absolute path",
        ));
    }
    let executable = std::fs::canonicalize(program)?;
    let path = executable
        .to_str()
        .ok_or_else(|| io::Error::other("non-UTF-8 launch executable"))?;
    let request = encode(
        LANDLOCK_RESOLVE,
        &ResolveLandlockParams {
            executable: path.into(),
        },
    )
    .map_err(io::Error::other)?;
    let reply = asc_daemon_client::call(socket, &request, timeout).map_err(io::Error::other)?;
    let result = match reply {
        DaemonResponse::Success(reply) => reply.result,
        DaemonResponse::Error(reply) => return Err(io::Error::other(reply.error.message())),
    };

    let scope = serde_json::from_value::<Option<PreparedScope>>(result)?.ok_or_else(|| {
        io::Error::other("no active Landlock scope matches this executable and user")
    })?;
    let [policy] = scope.policy_snapshots.as_slice() else {
        return Err(io::Error::other("invalid Landlock scope snapshot"));
    };
    let PolicySource::Cedar(source) = &policy.template else {
        return Err(io::Error::other("expected a Cedar Landlock scope policy"));
    };
    asc_landlock::install(source).map_err(io::Error::other)?;
    eprintln!(
        "Landlock scope {} installed (policy revision {})",
        scope.scope_id,
        policy.revision.get()
    );
    // Match the canonical path while preserving the name used to invoke the program.
    Err(Command::new(executable).args(args).arg0(program).exec())
}
