use std::io;
use std::process::ExitCode;

use asc_cli::{
    Cli, InputError, Plan,
    capabilities::process_environment,
    output::{
        render_binding_mutation, render_policy, render_scan_code, render_scan_prompt,
        warn_multi_turn_incomplete,
    },
};

fn main() -> ExitCode {
    let cli = match Cli::parse_from(std::env::args_os()) {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { 2 } else { 0 };
            return if error.print().is_ok() {
                ExitCode::from(code)
            } else {
                ExitCode::FAILURE
            };
        }
    };
    match run(&cli) {
        Ok(code) => ExitCode::from(code),
        // Scan commands own their usage hints, so those errors render
        // verbatim instead of behind the generic prefix.
        Err(RunError::Input(input)) if input.is_usage_hint() => {
            eprintln!("{input}");
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("agent-sec-cli: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<u8, RunError> {
    let socket = match cli.plan() {
        // The capability view describes the environment this process inherited,
        // so it must resolve it here rather than through a daemon.
        Plan::Local(command) => {
            return command
                .render(
                    &process_environment(),
                    &mut io::stdout().lock(),
                    &mut io::stderr().lock(),
                )
                .map_err(RunError::Output);
        }
        Plan::Daemon { socket } => socket,
    };
    // Scan-prompt resolves its own request batch (one per input line or
    // conversation payload) and prints diagnostics around them, so it owns
    // its transport loop instead of sharing the single-request path.
    if cli.is_scan_prompt() {
        let run = cli.prompt_scan_run().map_err(RunError::Input)?;
        for warning in &run.warnings {
            eprintln!("{warning}");
        }
        // An empty batch means the caller passed a blank --text: nothing to
        // scan, success, matching the V1 silent exit.
        let mut exit_code = 0;
        for request in &run.requests {
            let response = asc_daemon_client::call(socket, request, cli.timeout())
                .map_err(RunError::Client)?;
            let code = render_scan_prompt(
                &response,
                run.format,
                &mut io::stdout().lock(),
                &mut io::stderr().lock(),
            )
            .map_err(RunError::Output)?;
            if run.is_multi_turn {
                warn_multi_turn_incomplete(&response, &mut io::stderr().lock())
                    .map_err(RunError::Output)?;
            }
            exit_code = exit_code.max(code);
        }
        return Ok(exit_code);
    }
    let request = cli.request().map_err(RunError::Input)?;
    let response =
        asc_daemon_client::call(socket, &request, cli.timeout()).map_err(RunError::Client)?;
    if cli.is_scan_code() {
        render_scan_code(
            &response,
            &mut io::stdout().lock(),
            &mut io::stderr().lock(),
        )
        .map_err(RunError::Output)
    } else if matches!(
        request.method.as_str(),
        asc_daemon_protocol::method::POLICY_BINDINGS_CREATE
            | asc_daemon_protocol::method::POLICY_BINDINGS_UPDATE
            | asc_daemon_protocol::method::POLICY_BINDINGS_DELETE
    ) {
        render_binding_mutation(
            &response,
            &mut io::stdout().lock(),
            &mut io::stderr().lock(),
        )
        .map_err(RunError::Output)
    } else {
        render_policy(
            &response,
            &mut io::stdout().lock(),
            &mut io::stderr().lock(),
        )
        .map_err(RunError::Output)
    }
}

#[derive(Debug, thiserror::Error)]
enum RunError {
    #[error(transparent)]
    Input(#[from] InputError),
    #[error(transparent)]
    Client(#[from] asc_daemon_client::ClientError),
    #[error(transparent)]
    Output(#[from] io::Error),
}
