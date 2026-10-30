//! Daemon-only proposals after bounded collection; final choices create approval requests, not approvals.

mod git;
mod input;
mod render;
mod terminal;

use std::io::{self, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use asc_daemon_protocol::{
    DaemonRequest, DaemonResponse, ErrorCode, error_code,
    intent::{
        INTENT_REQUEST_BYTES, INTENT_RESULT_BYTES, INTENT_TASK_BYTES, IntentProposeParams,
        IntentProposeResult,
    },
    method::INTENT_PROPOSE,
};
use chrono::Utc;
use clap::{Args, Subcommand, ValueEnum};
use serde_json::Value;

#[derive(Debug, Subcommand)]
pub(crate) enum IntentCommand {
    /// Generate a pending read-only candidate. Task text is sent to the configured cloud model; file contents stay on this host.
    Propose(Propose),
}

#[derive(Debug, Args)]
pub(crate) struct Propose {
    /// Complete task text; never interpreted as CLI options.
    #[arg(long, allow_hyphen_values = true)]
    task: String,
    #[arg(
        long,
        help = "Explicitly collect Git worktree changes; otherwise send only the task, caller cwd and attachments"
    )]
    workspace: Option<PathBuf>,
    /// Explicit regular file or complete bounded directory; repeatable.
    #[arg(long = "attach")]
    attachments: Vec<PathBuf>,
    /// Candidate lifetime in seconds, starting at the daemon request time.
    #[arg(long, default_value_t = 1800, value_parser = clap::value_parser!(u32).range(1..=1800))]
    ttl: u32,
    /// JSON/Cedar and non-TTY output never request approval.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
    Cedar,
}

/// Redacted intent failures without task text, file contents or raw transport errors.
#[derive(Debug, thiserror::Error)]
pub enum IntentFailure {
    /// Input exceeds collection, task or transport budgets.
    #[error("intent input exceeds its budget; use smaller explicit --attach inputs")]
    Limit,
    /// Input is inaccessible, changed or of an unsupported type.
    #[error(
        "intent input is inaccessible, changed or unsupported; use regular files without symlinks"
    )]
    Unsafe,
    /// Additional materials or a new proposal are required.
    #[error("{0}")]
    Clarification(&'static str),
    /// Local daemon transport failed; no local fallback is enabled.
    #[error("intent daemon transport failed; no candidate or local fallback")]
    Transport,
    /// Server returned a safe error code with an operator hint.
    #[error("intent daemon rejected request: {code}{hint}")]
    Daemon {
        /// Canonical wire error code.
        code: ErrorCode,
        /// Routing or configuration context for codes that usually mean a client mistake.
        hint: String,
    },
    /// Candidate or response failed integrity checks.
    #[error("invalid intent daemon response; no approval request generated")]
    Response,
    /// Invalid evidence or incompatible daemon output must not appear as valid understanding.
    #[error(
        "invalid task evidence (empty field key or incompatible daemon version); rebuild and update the running daemon"
    )]
    Evidence,
    /// Display or delivery failed.
    #[error("intent terminal or output failed")]
    Output,
    /// User interrupted the operation; no approval request is generated.
    #[error("intent interrupted; no approval request generated")]
    Interrupted,
}

impl IntentFailure {
    /// Returns 2 for clarification, 130 for interruption and 1 for other execution errors.
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Clarification(_) => 2,
            Self::Interrupted => 130,
            _ => 1,
        }
    }
}

impl From<io::Error> for IntentFailure {
    fn from(_: io::Error) -> Self {
        Self::Output
    }
}
impl From<input::InputFailure> for IntentFailure {
    fn from(value: input::InputFailure) -> Self {
        match value {
            input::InputFailure::Limit => Self::Limit,
            input::InputFailure::Unsafe => Self::Unsafe,
            input::InputFailure::Clarification(message) => Self::Clarification(message),
        }
    }
}

impl IntentCommand {
    pub(crate) fn run(&self, socket: &Path, timeout: Duration) -> Result<u8, IntentFailure> {
        let Self::Propose(options) = self;
        let interrupted = Arc::new(AtomicBool::new(false));
        let signal = terminal::Interrupt::register(Arc::clone(&interrupted))?;
        let result = options.run(socket, timeout, &interrupted);
        drop(signal);
        check_interrupt(&interrupted)?;
        result
    }
}

impl Propose {
    fn run(
        &self,
        socket: &Path,
        timeout: Duration,
        interrupted: &AtomicBool,
    ) -> Result<u8, IntentFailure> {
        let interactive =
            self.format == Format::Text && io::stdin().is_terminal() && io::stdout().is_terminal();
        let mut task = self.task.clone();
        loop {
            check_interrupt(interrupted)?;
            if task.trim().is_empty() || task.len() > INTENT_TASK_BYTES {
                return Err(IntentFailure::Limit);
            }
            let collected = input::collect(self.workspace.as_deref(), &self.attachments)?;
            check_interrupt(interrupted)?;
            let result = self.propose(socket, timeout, &task, &collected);
            check_interrupt(interrupted)?;
            let result = result?;
            if let IntentProposeResult::Candidate { candidate } = &result {
                render::validate(candidate, &task, self.ttl, &collected)?;
                fresh(candidate)?;
            }
            render::validate_evidence(&result, &task)?;
            let code = render::render(&result, &task, self.format)?;
            let IntentProposeResult::Candidate { candidate } = &result else {
                return Ok(code);
            };
            if !interactive {
                return Ok(code);
            }
            loop {
                let choice = terminal::line(
                    "[a] Request approval  [m] Modify task  [v] View Cedar  [s] View scope  [q] Cancel > ",
                    16,
                    interrupted,
                )?;
                match choice.as_deref().map(str::trim) {
                    Some("a") => {
                        fresh(candidate)?;
                        let current = input::collect(self.workspace.as_deref(), &self.attachments)?;
                        check_interrupt(interrupted)?;
                        if current != collected {
                            return Err(IntentFailure::Clarification(
                                "Materials changed; submit a new proposal. The displayed candidate was not replaced.",
                            ));
                        }
                        render::validate(candidate, &task, self.ttl, &current)?;
                        fresh(candidate)?;
                        check_interrupt(interrupted)?;
                        render::approval_request(candidate, io::stdout().lock(), io::stderr())?;
                        return Ok(0);
                    }
                    Some("m") => {
                        let Some(revised) = terminal::line(
                            "Complete revised task > ",
                            INTENT_TASK_BYTES,
                            interrupted,
                        )?
                        else {
                            return Ok(4);
                        };
                        if revised.trim().is_empty() {
                            continue;
                        }
                        task = revised;
                        break;
                    }
                    Some("v") => render::view(candidate, true)?,
                    Some("s") => render::view(candidate, false)?,
                    Some("q") | None => return Ok(4),
                    _ => {}
                }
            }
        }
    }

    fn propose(
        &self,
        socket: &Path,
        timeout: Duration,
        task: &str,
        collected: &input::Collected,
    ) -> Result<IntentProposeResult, IntentFailure> {
        let params = IntentProposeParams {
            task: task.into(),
            working_directory: Some(collected.working_directory.clone()),
            ttl: self.ttl,
            scopes: collected.scopes.clone(),
            materials: collected.materials.clone(),
        };
        let request = DaemonRequest {
            method: INTENT_PROPOSE.into(),
            params: serde_json::to_value(params).map_err(|_| IntentFailure::Response)?,
            trace_context: None,
            compatibility: None,
        };
        // Reserve the newline; the server still checks line length after propagation injection.
        if serde_json::to_vec(&request)
            .map_err(|_| IntentFailure::Response)?
            .len()
            >= INTENT_REQUEST_BYTES
        {
            return Err(IntentFailure::Limit);
        }
        writeln!(
            io::stderr(),
            "Task text will be sent to the configured cloud model and may incur charges; file contents are sent only to the local daemon."
        )?;
        let response = asc_daemon_client::call(socket, &request, timeout)
            .map_err(|_| IntentFailure::Transport)?;
        let value = match response {
            DaemonResponse::Success(response) => response.result,
            DaemonResponse::Error(response) => {
                return Err(IntentFailure::Daemon {
                    hint: daemon_hint(&response.error.code, socket),
                    code: response.error.code,
                });
            }
        };
        if serde_json::to_vec(&value)
            .map_err(|_| IntentFailure::Response)?
            .len()
            > INTENT_RESULT_BYTES
        {
            return Err(IntentFailure::Response);
        }
        serde_json::from_value(value).map_err(|_| IntentFailure::Response)
    }
}

/// Names the socket and the usual causes when the daemon exposes no intent service.
///
/// An unavailable service covers both configuration and an unusable model answer, and an older
/// build answers `unknown_method`; without this hint the message never names the endpoint that
/// was actually contacted, which is the most common deployment mistake.
fn daemon_hint(code: &ErrorCode, socket: &Path) -> String {
    let socket = socket.display();
    match code.as_str() {
        error_code::UNAVAILABLE => format!(
            "; the intent service on {socket} is disabled or misconfigured, or the model returned no valid draft; check --socket or AGENT_SEC_DAEMON_SOCKET, ASC_INTENT_ENABLED=true and the model settings, then retry"
        ),
        error_code::UNKNOWN_METHOD => format!(
            "; {socket} does not register intent.propose, so it is an older daemon; check --socket or AGENT_SEC_DAEMON_SOCKET and restart the daemon built from this source tree"
        ),
        _ => String::new(),
    }
}

fn fresh(candidate: &Value) -> Result<(), IntentFailure> {
    if Utc::now().timestamp() >= render::expiry(candidate)? {
        Err(IntentFailure::Clarification(
            "Candidate expired; submit a new proposal. Expiry is never refreshed automatically.",
        ))
    } else {
        Ok(())
    }
}

fn check_interrupt(interrupted: &AtomicBool) -> Result<(), IntentFailure> {
    if interrupted.load(Ordering::Relaxed) {
        Err(IntentFailure::Interrupted)
    } else {
        Ok(())
    }
}
