//! Bridges the detection engine to the Action runtime.
//!
//! Everything in this module is translation: a decoded [`PromptScanRequest`]
//! becomes an engine [`ScanConfig`] and call, an engine [`ScanResult`] becomes
//! a [`PromptScanOutput`], and a [`ScannerError`] becomes a classified
//! [`ActionError`]. The detection logic itself stays in the engine modules,
//! unchanged from when it ran behind the V1 command line.

use std::sync::{Arc, Mutex};

use asc_action_runtime::{CapabilityExecutor, ExecutionContext};
use asc_action_types::{
    ActionError, ActionId, ConversationTurn, Finding, LayerFailure, LayerOutcome, ModelId,
    PromptScanOutput, PromptScanRequest, RiskLevel, ScanMode, ThreatType, Verdict,
};
use serde_json::{Map, Value};

use crate::config::{ScanConfig, ScanMode as EngineMode};
use crate::error::ScannerError;
use crate::models::multi_turn_intent::Turn;
use crate::models::qwen3_guard::MODEL_QWEN3_GUARD;
use crate::models::warden_gen::MODEL_WARDEN_GEN;
use crate::result::{
    ScanResult, ThreatType as EngineThreatType, Verdict as EngineVerdict, best_confidence, round_py,
};
use crate::scanner::PromptScanner;

/// Runs `prompt_scan` requests against the detection engine.
///
/// Scanners are reused rather than rebuilt per request: rule-set regex
/// compilation dominates construction, so a long-running daemon builds each
/// scanner once. The `fast` scanner has no model dependency and is built
/// eagerly; the model-backed and multi-turn scanners are built on first use so
/// a daemon that never runs them never contacts the model service.
pub struct PromptScanExecutor {
    /// Rule-engine-only scanner, always ready.
    fast: Arc<PromptScanner>,
    /// Default-model scanner shared by `standard` and `strict`, whose presets
    /// are identical today; a request naming a non-default model is served by
    /// a one-off scanner instead so it cannot evict this hot instance.
    standard: Mutex<Option<Arc<PromptScanner>>>,
    /// Conversation-level scanner for `multi_turn`.
    multi_turn: Mutex<Option<Arc<PromptScanner>>>,
}

impl PromptScanExecutor {
    /// Builds the executor and its always-ready `fast` scanner.
    ///
    /// # Errors
    /// Returns a classified [`ActionError`] when the rule engine cannot be
    /// constructed (e.g. a malformed built-in rule set), which is a defect
    /// rather than a request problem.
    pub fn new() -> Result<Self, ActionError> {
        let fast =
            PromptScanner::new(ScanConfig::preset(EngineMode::Fast)).map_err(map_scanner_error)?;
        Ok(Self {
            fast: Arc::new(fast),
            standard: Mutex::new(None),
            multi_turn: Mutex::new(None),
        })
    }

    /// Returns the scanner backing `mode`, building and caching it on first use.
    fn scanner_for(
        &self,
        mode: ScanMode,
        model: Option<ModelId>,
    ) -> Result<Arc<PromptScanner>, ScannerError> {
        match mode {
            ScanMode::Fast => Ok(Arc::clone(&self.fast)),
            ScanMode::Standard | ScanMode::Strict => match model {
                // A non-default model is a one-off build: caching it would let
                // one request's choice replace the default other requests use.
                Some(ModelId::WardenGen) => {
                    Self::build(EngineMode::Standard, MODEL_WARDEN_GEN).map(Arc::new)
                }
                Some(ModelId::Qwen3Guard) | None => {
                    Self::cached(&self.standard, EngineMode::Standard)
                }
            },
            ScanMode::MultiTurn => Self::cached(&self.multi_turn, EngineMode::MultiTurn),
        }
    }

    /// Returns the scanner in `slot`, building it under the lock on first use.
    fn cached(
        slot: &Mutex<Option<Arc<PromptScanner>>>,
        mode: EngineMode,
    ) -> Result<Arc<PromptScanner>, ScannerError> {
        // Poisoning means a prior build panicked mid-lock; a panic in scanner
        // construction is a defect, so surfacing it as a failed scan is better
        // than masking it.
        let mut guard = slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(scanner) = guard.as_ref() {
            return Ok(Arc::clone(scanner));
        }
        let scanner = Arc::new(Self::build(mode, MODEL_QWEN3_GUARD)?);
        *guard = Some(Arc::clone(&scanner));
        Ok(scanner)
    }

    /// Builds a scanner for `mode` with `model_name` as its L2 model.
    fn build(mode: EngineMode, model_name: &str) -> Result<PromptScanner, ScannerError> {
        let mut config = ScanConfig::preset(mode);
        model_name.clone_into(&mut config.model_name);
        PromptScanner::new(config)
    }
}

impl CapabilityExecutor for PromptScanExecutor {
    type Request = PromptScanRequest;
    type Output = PromptScanOutput;

    fn action_id(&self) -> ActionId {
        ActionId::PromptScan
    }

    fn validate(&self, request: &PromptScanRequest) -> Result<(), ActionError> {
        request.validate()
    }

    fn execute(
        &self,
        ctx: &ExecutionContext<'_>,
        request: &PromptScanRequest,
    ) -> Result<PromptScanOutput, ActionError> {
        // Building a scanner can compile a rule set or probe the model service,
        // so bail out for an already-gone caller before paying either cost.
        ctx.checkpoint()?;
        let scanner = self
            .scanner_for(request.mode, request.model)
            .map_err(map_scanner_error)?;
        // The scan itself is the long pole (a model round trip in the backed
        // modes); check once more before entering it.
        ctx.checkpoint()?;
        let result = if request.mode.is_conversational() {
            let history = to_turns(&request.history);
            scanner.scan_multi_turn(
                &history,
                &request.text,
                request.assistant_response.as_deref().unwrap_or(""),
                request.source.as_deref(),
            )
        } else {
            scanner.scan(&request.text, request.source.as_deref())
        };
        to_output(&result.map_err(map_scanner_error)?, request.mode)
    }

    fn audit_verdict(&self, output: &PromptScanOutput) -> Option<Verdict> {
        Some(output.verdict)
    }
}

/// Converts request history into the engine's tolerant [`Turn`] form.
///
/// The role set is already closed by [`ConversationTurn`], so each turn maps
/// to the canonical object form the engine's role normaliser expects.
fn to_turns(history: &[ConversationTurn]) -> Vec<Turn> {
    history
        .iter()
        .map(|turn| Turn::Message {
            role: Some(Value::String(turn.role.as_str().to_owned())),
            content: Some(Value::String(turn.content.clone())),
        })
        .collect()
}

/// Projects an engine [`ScanResult`] onto the Action's output contract.
///
/// The published float precision matches what the engine emitted on the wire
/// (scores to four places, timings to two) so a caller sees the same numbers
/// the scanner has always reported.
fn to_output(result: &ScanResult, mode: ScanMode) -> Result<PromptScanOutput, ActionError> {
    let verdict = map_verdict(result.verdict)?;
    let failed = layers_failed(&result.metadata);
    Ok(PromptScanOutput {
        verdict,
        risk_level: RiskLevel::from(verdict),
        threat_type: map_threat_type(result.threat_type),
        // Confidence backs a positive verdict only; a clean scan reports none.
        confidence: result
            .is_threat
            .then(|| round_py(best_confidence(&result.layer_results), 3)),
        summary: result.build_summary(),
        findings: result
            .layer_results
            .iter()
            .flat_map(|layer| layer.details.iter())
            .map(|detail| Finding {
                rule_id: detail.rule_id.clone(),
                description: detail.description.clone(),
                evidence: detail.matched_text.clone(),
                category: detail.category.clone(),
            })
            .collect(),
        layer_results: result
            .layer_results
            .iter()
            .map(|layer| LayerOutcome {
                layer: layer.layer_name.clone(),
                detected: layer.detected,
                score: layer.score.map(|score| round_py(score, 4)),
                latency_ms: round_py(layer.latency_ms, 2),
            })
            .collect(),
        degraded: !failed.is_empty(),
        layers_failed: failed,
        input_truncated: metadata_bool(&result.metadata, "input_truncated"),
        input_bytes_scanned: metadata_u64(&result.metadata, "input_bytes_scanned"),
        engine_version: crate::ENGINE_VERSION.to_owned(),
        scan_ms: round_py(result.latency_ms, 2),
        mode,
    })
}

/// Maps the engine verdict onto the Action verdict.
///
/// # Errors
/// The engine's `Error` verdict is an execution failure, not a business
/// outcome, so it becomes an internal [`ActionError`]: the Action verdict has
/// no failure variant precisely so an outage can never read as a safe result.
fn map_verdict(verdict: EngineVerdict) -> Result<Verdict, ActionError> {
    match verdict {
        EngineVerdict::Pass => Ok(Verdict::Pass),
        EngineVerdict::Warn => Ok(Verdict::Warn),
        EngineVerdict::Deny => Ok(Verdict::Deny),
        EngineVerdict::Error => Err(ActionError::internal(
            "scan pipeline reported an error verdict",
        )),
    }
}

/// Maps the engine threat class onto the Action threat class, one to one.
fn map_threat_type(threat: EngineThreatType) -> ThreatType {
    match threat {
        EngineThreatType::DirectInjection => ThreatType::DirectInjection,
        EngineThreatType::IndirectInjection => ThreatType::IndirectInjection,
        EngineThreatType::Jailbreak => ThreatType::Jailbreak,
        EngineThreatType::Unsafe => ThreatType::Unsafe,
        EngineThreatType::Benign => ThreatType::Benign,
        EngineThreatType::NotScanned => ThreatType::NotScanned,
    }
}

/// Classifies a [`ScannerError`] as an [`ActionError`] for the daemon to
/// project onto a transport error code.
///
/// A dependency outage (model not pulled, service unreachable, a mandatory
/// layer missing) is `dependency_unavailable`; an empty or unusable input is
/// `invalid_input`; a configuration fault is `internal`, since the caller
/// cannot pick the model name or layer set. The messages are engine-authored
/// and carry no scanned content.
fn map_scanner_error(error: ScannerError) -> ActionError {
    match error {
        ScannerError::Input(message) => ActionError::invalid_input(message),
        ScannerError::Config(message) => {
            ActionError::internal(format!("scanner configuration error: {message}"))
        }
        ScannerError::LayerNotAvailable(message)
        | ScannerError::ModelLoad(message)
        | ScannerError::ModelInference(message) => ActionError::dependency_unavailable(message),
        ScannerError::ModelClient(source) => {
            ActionError::dependency_unavailable(source.to_string())
        }
    }
}

/// Extracts the pipeline's failed-layer notes, renaming `error` to `reason`.
fn layers_failed(metadata: &Map<String, Value>) -> Vec<LayerFailure> {
    metadata
        .get("layers_failed")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .map(|entry| LayerFailure {
                    layer: string_field(entry, "layer"),
                    reason: string_field(entry, "error"),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Reads a string field from a JSON object, empty when absent or not a string.
fn string_field(entry: &Value, key: &str) -> String {
    entry
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Reads a boolean scan-accounting field, defaulting to `false`.
fn metadata_bool(metadata: &Map<String, Value>, key: &str) -> bool {
    metadata.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// Reads a `u64` scan-accounting field, defaulting to `0`.
fn metadata_u64(metadata: &Map<String, Value>, key: &str) -> u64 {
    metadata.get(key).and_then(Value::as_u64).unwrap_or(0)
}
