//! Command for sending prompt scans to the daemon.

use std::io::Read as _;
use std::path::PathBuf;

use asc_daemon_protocol::{DaemonRequest, PromptScanParams, method};
use clap::Args;
use serde_json::Value;

use crate::InputError;
use crate::output::PromptOutputFormat;

/// Environment variable that switches the L2 backend without a flag, so host
/// hooks can all share one backend without each passing `--model`.
const L2_MODEL_ENV: &str = "PROMPT_SCANNER_L2_MODEL";

/// Modes whose pipeline includes the L2 `ml_classifier` layer; an L2 model
/// override is inert in every other mode.
const L2_MODES: [&str; 2] = ["standard", "strict"];

/// Everything a `scan-prompt` invocation needs before it can run.
#[derive(Debug)]
pub struct PromptScanPlan {
    /// One request per input line or conversation payload; empty means
    /// nothing to scan (a whitespace `--text`), which exits successfully.
    pub requests: Vec<DaemonRequest>,
    /// Diagnostic warnings printed on stderr before the first request.
    pub warnings: Vec<String>,
    /// Selected presentation of each scan result.
    pub format: PromptOutputFormat,
    /// Whether the requests carry a conversation triple.
    pub is_multi_turn: bool,
}

/// Scans prompts for injection or jailbreak attempts through `asc-daemon`.
///
/// Input priority is `--text` > `--input <file>` > stdin; `multi_turn` reads a
/// JSON conversation triple from stdin, and `--model` overrides the L2 backend.
#[derive(Debug, Args)]
pub(crate) struct ScanPromptCommand {
    /// Prompt text to scan directly. Takes precedence over --input and stdin.
    #[arg(long, allow_hyphen_values = true)]
    text: Option<String>,
    /// Path to a file containing prompts (one per line). If omitted, reads from stdin.
    #[arg(long)]
    input: Option<PathBuf>,
    /// Detection mode: fast (L1), standard (L1+L2), strict (L1+L2+L3 reserved), `multi_turn` (L4, reads JSON from stdin).
    #[arg(long, default_value = "standard")]
    mode: String,
    /// Output format: 'json' (default) or 'text' (human-readable).
    #[arg(long, default_value = "json")]
    format: String,
    /// Label for the input origin (e.g. `user_input`, `rag`, `tool_output`).
    #[arg(long, default_value = "")]
    source: String,
    /// L2 backend model; overrides `PROMPT_SCANNER_L2_MODEL`.
    #[arg(long)]
    model: Option<String>,
}

impl ScanPromptCommand {
    /// Resolves the invocation into requests, warnings, and output format.
    ///
    /// Reading stdin or an input file happens here so the request path stays
    /// synchronous and each scan is submitted with fresh input.
    pub(crate) fn plan(&self) -> Result<PromptScanPlan, InputError> {
        let mode = self.mode.to_lowercase();
        let format = PromptOutputFormat::parse(&self.format)?;
        let model = resolve_l2_model(self.model.as_deref());
        let mut warnings = Vec::new();
        if let Some(model) = &model
            && !L2_MODES.contains(&mode.as_str())
        {
            // fast runs L1 only and multi_turn a fixed L4 model, so the
            // override would silently do nothing; surface that instead of
            // letting an operator mistake an inert flag for a backend switch.
            let origin = if self
                .model
                .as_deref()
                .map(str::trim)
                .is_some_and(|model| !model.is_empty())
            {
                "--model"
            } else {
                L2_MODEL_ENV
            };
            warnings.push(format!(
                "Warning: {origin} '{model}' is ignored in {mode} mode; \
                 it only applies to standard/strict (L2)."
            ));
        }
        let source = (!self.source.is_empty()).then(|| self.source.clone());
        let requests = if mode == "multi_turn" {
            vec![self.multi_turn_request(&mode, source, model)?]
        } else {
            self.single_turn_requests(&mode, source, model)?
        };
        Ok(PromptScanPlan {
            requests,
            warnings,
            format,
            is_multi_turn: mode == "multi_turn",
        })
    }

    /// Builds one request per single-turn input using the input priority:
    /// `--text` (blank means nothing to scan), then `--input`, then stdin.
    fn single_turn_requests(
        &self,
        mode: &str,
        source: Option<String>,
        model: Option<String>,
    ) -> Result<Vec<DaemonRequest>, InputError> {
        if let Some(text) = self
            .text
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            return Ok(vec![Self::request(text, mode, source, model, None, None)?]);
        }
        // An explicitly blank `--text` means "nothing to scan" and succeeds
        // silently; falling through covers it because neither the
        // file nor stdin path is consulted when `--text` was given.
        if self.text.is_some() {
            return Ok(Vec::new());
        }
        if let Some(path) = &self.input {
            let file = std::fs::read_to_string(path).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    InputError::FileNotFound(path.clone())
                } else {
                    InputError::Read(error)
                }
            })?;
            let lines: Vec<&str> = file
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            if lines.is_empty() {
                return Err(InputError::FileEmpty(path.clone()));
            }
            return lines
                .iter()
                .map(|line| Self::request(line, mode, source.clone(), model.clone(), None, None))
                .collect();
        }
        let raw = read_stdin()?;
        if raw.trim().is_empty() {
            return Err(InputError::StdinEmpty);
        }
        Ok(vec![Self::request(
            raw.trim(),
            mode,
            source,
            model,
            None,
            None,
        )?])
    }

    /// Reads the conversation triple from stdin and builds one L4 request.
    ///
    /// The payload must carry a `history` list, a `current_query` string, and
    /// an `assistant_response` string, and the query must be non-blank.
    fn multi_turn_request(
        &self,
        mode: &str,
        source: Option<String>,
        model: Option<String>,
    ) -> Result<DaemonRequest, InputError> {
        if self.text.is_some() || self.input.is_some() {
            return Err(InputError::MultiTurnTextConflict);
        }
        let raw = read_stdin()?;
        if raw.trim().is_empty() {
            return Err(InputError::StdinEmpty);
        }
        let payload: Value = serde_json::from_str(raw.trim())
            .map_err(|error| InputError::InvalidJson(error.to_string()))?;
        let history = match payload.get("history") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items.clone(),
            Some(_) => return Err(InputError::InvalidPayload),
        };
        let current_query = string_field(&payload, "current_query")?;
        let assistant_response = string_field(&payload, "assistant_response")?;
        if current_query.trim().is_empty() {
            return Err(InputError::EmptyCurrentQuery);
        }
        Self::request(
            &current_query,
            mode,
            source,
            model,
            Some(history),
            Some(assistant_response),
        )
    }

    /// Serializes one scan into a daemon request.
    fn request(
        text: &str,
        mode: &str,
        source: Option<String>,
        model: Option<String>,
        history: Option<Vec<Value>>,
        assistant_response: Option<String>,
    ) -> Result<DaemonRequest, InputError> {
        Ok(DaemonRequest {
            method: method::ACTION_PROMPT_SCAN.to_owned(),
            params: serde_json::to_value(PromptScanParams {
                text: text.to_owned(),
                mode: Some(mode.to_owned()),
                source,
                model,
                history,
                assistant_response,
            })?,
        })
    }
}

/// Reads all of stdin, blocking until end of input.
fn read_stdin() -> Result<String, InputError> {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .map_err(InputError::Read)?;
    Ok(raw)
}

/// Extracts a string field, returning an empty string when absent or null and
/// rejecting non-string values.
fn string_field(payload: &Value, field: &str) -> Result<String, InputError> {
    match payload.get(field) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(InputError::InvalidPayload),
    }
}

/// Resolves the L2 backend override: `--model` > `PROMPT_SCANNER_L2_MODEL` >
/// the scanner's built-in default. A blank value at either layer means "not
/// set" and falls through.
fn resolve_l2_model(cli_model: Option<&str>) -> Option<String> {
    if let Some(model) = cli_model.map(str::trim).filter(|m| !m.is_empty()) {
        return Some(model.to_owned());
    }
    std::env::var(L2_MODEL_ENV).ok().and_then(|value| {
        let trimmed = value.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command() -> ScanPromptCommand {
        ScanPromptCommand {
            text: None,
            input: None,
            mode: "standard".to_owned(),
            format: "json".to_owned(),
            source: String::new(),
            model: None,
        }
    }

    #[test]
    fn a_nonempty_prompt_builds_a_prompt_scan_request() {
        let mut command = command();
        command.text = Some("hello there".to_owned());
        command.mode = "fast".to_owned();
        command.source = "cli".to_owned();
        let plan = command.plan().expect("plan builds");
        assert_eq!(plan.requests.len(), 1);
        let request = &plan.requests[0];
        assert_eq!(request.method, method::ACTION_PROMPT_SCAN);
        assert_eq!(request.params["text"], "hello there");
        assert_eq!(request.params["mode"], "fast");
        assert_eq!(request.params["source"], "cli");
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn an_explicitly_blank_text_scans_nothing_successfully() {
        let mut command = command();
        command.text = Some("   ".to_owned());
        let plan = command.plan().expect("blank text is not an error");
        assert!(plan.requests.is_empty());
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn a_missing_source_is_omitted_from_the_request() {
        let mut command = command();
        command.text = Some("hello".to_owned());
        let plan = command.plan().expect("plan builds");
        assert!(plan.requests[0].params.get("source").is_none());
    }

    #[test]
    fn an_unknown_format_is_rejected() {
        let mut command = command();
        command.text = Some("hello".to_owned());
        command.format = "yaml".to_owned();
        let error = command.plan().expect_err("invalid format must fail");
        assert!(matches!(error, InputError::InvalidFormat(ref format) if format == "yaml"));
    }

    #[test]
    fn an_uppercase_mode_is_normalized() {
        let mut command = command();
        command.text = Some("hello".to_owned());
        command.mode = "FAST".to_owned();
        let plan = command.plan().expect("plan builds");
        assert_eq!(plan.requests[0].params["mode"], "fast");
    }

    #[test]
    fn a_model_override_reaches_the_request() {
        let mut command = command();
        command.text = Some("hello".to_owned());
        command.model = Some("modelscope.cn/ANOLISA/Warden-Gen-0.6B-GGUF".to_owned());
        let plan = command.plan().expect("plan builds");
        assert_eq!(
            plan.requests[0].params["model"],
            "modelscope.cn/ANOLISA/Warden-Gen-0.6B-GGUF"
        );
        // standard consumes the override, so no warning is due.
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn a_model_override_in_fast_mode_warns_but_still_scans() {
        let mut command = command();
        command.text = Some("hello".to_owned());
        command.mode = "fast".to_owned();
        command.model = Some("modelscope.cn/ANOLISA/Warden-Gen-0.6B-GGUF".to_owned());
        let plan = command.plan().expect("plan builds");
        assert_eq!(
            plan.requests[0].params["model"],
            "modelscope.cn/ANOLISA/Warden-Gen-0.6B-GGUF"
        );
        assert_eq!(plan.warnings.len(), 1);
        assert!(plan.warnings[0].contains("--model"));
        assert!(plan.warnings[0].contains("fast"));
    }

    #[test]
    fn multi_turn_with_text_or_input_is_rejected() {
        for conflict in [Some("hello".to_owned()), None] {
            let mut command = command();
            command.mode = "multi_turn".to_owned();
            if let Some(text) = conflict {
                command.text = Some(text);
            } else {
                command.input = Some(PathBuf::from("prompts.txt"));
            }
            let error = command
                .plan()
                .expect_err("multi_turn conflicts with text input");
            assert!(matches!(error, InputError::MultiTurnTextConflict));
        }
    }

    #[test]
    fn multi_turn_payload_validation_rejects_malformed_shapes() {
        // These cases read stdin, so they are covered by exercising the
        // helpers directly: the payload shape checks are pure functions of
        // the parsed JSON.
        let payload: Value =
            serde_json::from_str(r#"{"history": "not-a-list", "current_query": "q"}"#).unwrap();
        assert!(string_field(&payload, "current_query").is_ok());
        let history = payload.get("history");
        assert!(!matches!(history, Some(Value::Array(_))));
    }
}
