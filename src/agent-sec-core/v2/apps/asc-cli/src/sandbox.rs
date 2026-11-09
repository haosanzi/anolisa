//! Policy-driven sandbox execution, PDP-authorized execution and the internal Cosh
//! authorization handoff.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use asc_daemon_protocol::authorization::{
    AgentPrincipal, AuthorizationRequest, Decision, ExecutionReceipt, ExecutionResult, LaunchSpec,
    OsPermissionSet, ReceiptAck,
};
use asc_pep_runtime::{
    ApprovalHandler, AuthorizationClient, DaemonAuthorizationClient, FixedPermissions, PepError,
    PepRuntime, SandboxBackend, prepare_launch,
};
use clap::{ArgGroup, Args, Subcommand};

pub mod hook;

const MAX_PERMISSION_BYTES: u64 = 4 * 1024 * 1024;

/// Sandbox execution entry points.
#[derive(Debug, Subcommand)]
pub enum SandboxCommand {
    /// Run a command inside the sandbox the policy authorizes.
    Run(SandboxRun),
    /// Internal Cosh authorization and execution handoff.
    #[command(subcommand, hide = true)]
    Hook(hook::HookCommand),
}

/// Inputs to one sandbox launch.
///
/// The caller names the policy; deriving the OS permission set from it is an internal step.
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("source").required(true).args(["policy", "permissions"])))]
pub struct SandboxRun {
    /// Cedar policy file; the same text `policy create` publishes.
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// Raw OS permission set, bypassing the policy projection.
    #[arg(long)]
    pub permissions: Option<PathBuf>,
    /// Print the projected OS permission set and launch nothing.
    #[arg(long)]
    pub dry_run: bool,
    /// Logical agent identity; together with `--agent-type` it authorizes through the daemon PDP.
    #[arg(long, requires = "agent_type")]
    pub agent_id: Option<String>,
    /// Agent family reported to the PDP, such as cosh.
    #[arg(long, requires = "agent_id")]
    pub agent_type: Option<String>,
    /// Ask for local approval when the PDP returns `STEP_UP`.
    #[arg(long)]
    pub ask: bool,
    /// Target executable and arguments, following `--`; optional only for `--dry-run`.
    #[arg(last = true, num_args = 1..)]
    pub command: Vec<String>,
}

impl SandboxCommand {
    /// Installs the supplied restrictions and returns the target's exit status.
    ///
    /// # Errors
    /// Rejects malformed permissions, unsupported restrictions and launch failures.
    pub fn run(&self, socket: Option<&Path>, timeout: Duration) -> Result<u8, SandboxError> {
        let options = match self {
            Self::Run(options) => options,
            Self::Hook(command) => {
                return command.run(
                    socket.ok_or_else(|| {
                        SandboxError::Execution("authorization socket missing".into())
                    })?,
                    timeout,
                );
            }
        };
        let permissions = options.requested()?;
        if options.dry_run {
            println!("{}", serde_json::to_string_pretty(&permissions)?);
            return Ok(0);
        }
        let (program, args) = options
            .command
            .split_first()
            .ok_or(SandboxError::MissingCommand)?;
        let launch = prepare_launch(
            program,
            args.to_vec(),
            &std::env::current_dir()?,
            target_environment()?,
        )?;
        let result = match (&options.agent_id, &options.agent_type) {
            (Some(agent_id), Some(agent_type)) => authorized(
                socket.ok_or_else(|| {
                    SandboxError::Execution("authorization socket missing".into())
                })?,
                timeout,
                &AgentPrincipal {
                    agent_id: agent_id.clone(),
                    agent_type: agent_type.clone(),
                },
                launch,
                permissions,
                options.ask,
            )?,
            _ => asc_pep_runtime::execute(launch, permissions)?,
        };
        exit_status(result)
    }
}

impl SandboxRun {
    /// Requests exactly what the named policy grants; the PDP narrows it further.
    fn requested(&self) -> Result<OsPermissionSet, SandboxError> {
        let Some(path) = &self.policy else {
            return match self.permissions.as_deref() {
                Some(path) => read_permissions(path),
                None => Err(SandboxError::MissingPermissions),
            };
        };
        let text = fs::read_to_string(path)?;
        let profile = asc_policy_os_permission::project(&text)
            .map_err(|error| SandboxError::Projection(error.to_string()))?;
        report(&profile);
        Ok(profile.permissions)
    }
}

/// Prints what the projection recovered before the launch decides anything.
fn report(profile: &asc_policy_os_permission::SandboxProfile) {
    for warning in &profile.report.warnings {
        eprintln!("POLICY_WARNING {warning}");
    }
    for statement in &profile.report.unprojected {
        eprintln!("POLICY_UNPROJECTED {statement}");
    }
    if !profile.report.launch_permitted {
        eprintln!(
            "POLICY_NO_LAUNCH_GRANT the policy permits neither process.spawn nor file.exec, so every launch is denied"
        );
    }
}

/// Evaluates the request through the daemon PDP and executes only the narrowed result.
fn authorized(
    socket: &std::path::Path,
    timeout: std::time::Duration,
    principal: &AgentPrincipal,
    launch: LaunchSpec,
    permissions: OsPermissionSet,
    ask: bool,
) -> Result<ExecutionResult, SandboxError> {
    let mut runtime = PepRuntime::new(SandboxBackend::installed()?);
    let client = ReportingClient(DaemonAuthorizationClient {
        socket: socket.to_path_buf(),
        timeout,
    });
    let mut approval = TerminalApproval;
    let channel: Option<&mut dyn ApprovalHandler> = ask.then_some(&mut approval);
    let outcome = runtime.run(
        principal,
        launch,
        &FixedPermissions(permissions),
        &client,
        channel,
    )?;
    // The decision is the enforcement evidence; the target keeps stdout and stderr.
    eprintln!(
        "PEP_DECISION {}",
        serde_json::json!({
            "decision_id": outcome.decision.decision_id,
            "policy_version": outcome.decision.policy_version,
            "verdict": outcome.decision.verdict,
            "warnings": outcome.decision.warnings,
            "receipt_error": outcome.receipt_error,
        })
    );
    Ok(outcome.result)
}

/// Forwards policy warnings to stderr without altering the decision.
struct ReportingClient(DaemonAuthorizationClient);

impl AuthorizationClient for ReportingClient {
    fn evaluate(&self, request: &AuthorizationRequest) -> Result<Decision, PepError> {
        let decision = self.0.evaluate(request)?;
        for warning in &decision.warnings {
            eprintln!("POLICY_WARNING {warning}");
        }
        Ok(decision)
    }

    fn report(&self, receipt: &ExecutionReceipt) -> Result<ReceiptAck, PepError> {
        self.0.report(receipt)
    }
}

/// Prompts on the terminal when the PDP requires step-up approval.
struct TerminalApproval;

impl ApprovalHandler for TerminalApproval {
    fn ask(&mut self, decision: &Decision) -> Result<bool, PepError> {
        use std::io::Write as _;

        eprintln!(
            "APPROVAL_REQUIRED {} {:?}",
            decision.launch.program, decision.launch.args
        );
        eprint!("Allow this invocation? [y/N] ");
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        Ok(matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "y" | "yes"
        ))
    }
}

fn target_environment() -> Result<BTreeMap<String, String>, SandboxError> {
    std::env::vars_os()
        .map(|(key, value)| {
            Ok((
                key.into_string().map_err(|_| SandboxError::Environment)?,
                value.into_string().map_err(|_| SandboxError::Environment)?,
            ))
        })
        .collect()
}

fn exit_status(
    result: asc_daemon_protocol::authorization::ExecutionResult,
) -> Result<u8, SandboxError> {
    if let Some(error) = result.error {
        return Err(SandboxError::Execution(error));
    }
    if let Some(signal) = result.cancel_signal {
        return Ok(u8::try_from(128_i32.saturating_add(signal)).unwrap_or(255));
    }
    if !result.installed || !result.started {
        return Err(SandboxError::Execution(
            "target was not started in a sandbox".into(),
        ));
    }
    if let Some(signal) = result.signal {
        return Ok(u8::try_from(128_i32.saturating_add(signal)).unwrap_or(255));
    }
    result
        .exit_code
        .and_then(|code| u8::try_from(code).ok())
        .ok_or_else(|| SandboxError::Execution("target did not return an exit status".into()))
}

pub(crate) fn read_permissions(path: &std::path::Path) -> Result<OsPermissionSet, SandboxError> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_PERMISSION_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PERMISSION_BYTES {
        return Err(SandboxError::TooLarge);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// Direct sandbox input and execution failures.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// The required target was absent.
    #[error("sandbox run requires a command after --")]
    MissingCommand,
    /// Permission input is bounded independently of its parsed structure.
    #[error("sandbox permissions exceed the 4 MiB input limit")]
    TooLarge,
    /// JSON contracts cannot preserve non-Unicode environment values.
    #[error("sandbox environment must be valid UTF-8")]
    Environment,
    /// Local file or working directory could not be read.
    #[error("cannot read sandbox input: {0}")]
    Io(#[from] std::io::Error),
    /// The permission object did not match the supported schema.
    #[error("invalid sandbox permissions: {0}")]
    Json(#[from] serde_json::Error),
    /// Permissions or runtime prerequisites could not be applied.
    #[error(transparent)]
    Runtime(#[from] asc_pep_runtime::PepError),
    /// The backend reported a failed installation or launch.
    #[error("sandbox execution failed: {0}")]
    Execution(String),
    /// The policy cannot be turned into the OS permission contract.
    #[error("policy projection failed: {0}")]
    Projection(String),
    /// No policy or permission set was supplied.
    #[error("sandbox run requires --policy or --permissions")]
    MissingPermissions,
}
