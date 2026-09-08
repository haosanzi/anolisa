//! Wire contract for the `prompt_scan` Action.
//!
//! Field names are camelCase and unknown fields are rejected, matching the
//! rest of the V2 daemon surface. Enum values stay lower snake case, which is
//! also what the scan engine has always published.

use serde::{Deserialize, Serialize};

use crate::result::{ActionError, Verdict};

/// Maximum encoded UTF-8 bytes accepted in [`PromptScanRequest::source`].
pub const MAX_SOURCE_BYTES: usize = 128;

/// Detection depth requested for one scan.
///
/// Wire values are exact and lower snake case. Unlike the V1 command line,
/// no case folding is applied: a JSON caller gets a decode failure naming the
/// expected values instead of a silently different mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    /// Rule engine only. No model dependency.
    Fast,
    /// Rule engine plus the model classifier. The default.
    #[default]
    Standard,
    /// Reserved for a stricter policy; currently identical to `Standard`.
    Strict,
    /// Conversation-level intent judgement, which replaces the other layers
    /// because it consumes a richer input.
    MultiTurn,
}

impl ScanMode {
    /// Returns the stable wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::Strict => "strict",
            Self::MultiTurn => "multi_turn",
        }
    }

    /// Returns whether this mode consumes a conversation rather than one prompt.
    pub const fn is_conversational(self) -> bool {
        matches!(self, Self::MultiTurn)
    }

    /// Returns whether this mode runs the selectable content-safety model.
    pub const fn uses_selectable_model(self) -> bool {
        matches!(self, Self::Standard | Self::Strict)
    }
}

/// Selectable content-safety model for the `standard` and `strict` modes.
///
/// The wire value is a symbolic name, never a model registry path or URL, so
/// a caller can pick between vetted classifiers without being able to steer
/// the scanner at an arbitrary model or endpoint. Resolving a name to a
/// deployed model is the capability's job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelId {
    /// `Qwen3Guard` generative content-safety classifier.
    Qwen3Guard,
    /// Warden generative content-safety classifier.
    WardenGen,
}

impl ModelId {
    /// Returns the stable wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Qwen3Guard => "qwen3_guard",
            Self::WardenGen => "warden_gen",
        }
    }
}

/// Author of one prior conversation turn.
///
/// The set is closed so an unrecognised label is reported to the caller
/// instead of reaching the judge prompt as an anonymous turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnRole {
    /// End user.
    User,
    /// Model under inspection.
    Assistant,
    /// System or developer instruction.
    System,
}

impl TurnRole {
    /// Returns the stable wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::System => "system",
        }
    }
}

/// One prior conversation turn supplied for a `multi_turn` scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationTurn {
    /// Who produced this turn.
    pub role: TurnRole,
    /// Turn text as the caller recorded it.
    pub content: String,
}

/// One `prompt_scan` invocation.
///
/// Cross-field rules are in [`PromptScanRequest::validate`]; serde only
/// checks the wire shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PromptScanRequest {
    /// Text to inspect. For `multi_turn` this is the current user query.
    pub text: String,
    /// Detection depth. Defaults to [`ScanMode::Standard`].
    #[serde(default)]
    pub mode: ScanMode,
    /// Caller-declared provenance of `text`, such as a tool name.
    ///
    /// Recorded for audit correlation only. It is self-reported, so it must
    /// never influence authorization or the verdict.
    #[serde(default)]
    pub source: Option<String>,
    /// Content-safety model to use. Only meaningful for `standard`/`strict`.
    #[serde(default)]
    pub model: Option<ModelId>,
    /// Prior turns, oldest first. Only accepted for `multi_turn`.
    ///
    /// The engine judges the most recent 32 turns; older ones are dropped
    /// rather than rejected.
    #[serde(default)]
    pub history: Vec<ConversationTurn>,
    /// Assistant reply under judgement. Only accepted for `multi_turn`, and
    /// absent when the exchange is being screened before a reply exists.
    #[serde(default)]
    pub assistant_response: Option<String>,
}

impl PromptScanRequest {
    /// Validates value and cross-field rules after serde has decoded the wire
    /// shape.
    ///
    /// Fields that the requested mode cannot act on are rejected rather than
    /// ignored: silently dropping conversation history would report a
    /// single-prompt verdict that the caller reads as a conversation verdict.
    ///
    /// # Errors
    /// Returns [`ActionError::invalid_input`] naming the offending field.
    pub fn validate(&self) -> Result<(), ActionError> {
        if self.text.trim().is_empty() {
            return Err(ActionError::invalid_input("text must not be blank"));
        }
        if let Some(source) = &self.source
            && source.len() > MAX_SOURCE_BYTES
        {
            return Err(ActionError::invalid_input(format!(
                "source must not exceed {MAX_SOURCE_BYTES} bytes"
            )));
        }
        if !self.mode.is_conversational() {
            if !self.history.is_empty() {
                return Err(ActionError::invalid_input(
                    "history is only accepted in multi_turn mode",
                ));
            }
            if self.assistant_response.is_some() {
                return Err(ActionError::invalid_input(
                    "assistantResponse is only accepted in multi_turn mode",
                ));
            }
        }
        if self.model.is_some() && !self.mode.uses_selectable_model() {
            return Err(ActionError::invalid_input(
                "model is only accepted in standard and strict modes",
            ));
        }
        Ok(())
    }
}

/// Coarse grading of a [`Verdict`] for consumers that report rather than gate.
///
/// This is a projection of the verdict, not an independent judgement:
/// [`From<Verdict>`](RiskLevel::from) is the only intended constructor, so the
/// two can never disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Corresponds to [`Verdict::Pass`].
    Low,
    /// Corresponds to [`Verdict::Warn`].
    Medium,
    /// Corresponds to [`Verdict::Deny`].
    High,
}

impl From<Verdict> for RiskLevel {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Pass => Self::Low,
            Verdict::Warn => Self::Medium,
            Verdict::Deny => Self::High,
        }
    }
}

/// Threat class a scan settled on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    /// The inspected text itself carries the injection payload.
    DirectInjection,
    /// The payload arrived through retrieval, tool output, or stored context.
    IndirectInjection,
    /// An attempt to shed safety restrictions or assume another role.
    Jailbreak,
    /// Content-safety threat confirmed by a model layer.
    Unsafe,
    /// No threat found.
    Benign,
    /// No detection layer produced a judgement.
    NotScanned,
}

/// One matched detection rule or model signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Finding {
    /// Rule identity, such as `INJ-001`.
    pub rule_id: String,
    /// Why this finding fired.
    pub description: String,
    /// Excerpt of the caller's own input that matched.
    pub evidence: String,
    /// Attack category the rule belongs to.
    pub category: String,
}

/// What one detection layer reported.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LayerOutcome {
    /// Layer name, such as `rule_engine`.
    pub layer: String,
    /// Whether this layer found a threat.
    pub detected: bool,
    /// Confidence in `0.0..=1.0`, absent when the backend reports none.
    pub score: Option<f64>,
    /// Time spent in this layer.
    pub latency_ms: f64,
}

/// A configured layer that could not answer.
///
/// A missing layer reduces coverage; it is not a failed request. The field is
/// named `reason` rather than `error` so it is not mistaken for the
/// invocation-level failure contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LayerFailure {
    /// Layer that dropped out.
    pub layer: String,
    /// Operator-facing cause.
    pub reason: String,
}

/// Result of one completed `prompt_scan`.
///
/// A result with `degraded` set is still a successful execution: the verdict
/// reflects only the layers that answered, so a caller requiring full
/// coverage must gate on `degraded` rather than on the verdict alone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PromptScanOutput {
    /// Gate decision.
    pub verdict: Verdict,
    /// Grading projected from `verdict`.
    pub risk_level: RiskLevel,
    /// Threat class behind the verdict.
    pub threat_type: ThreatType,
    /// Confidence behind a positive verdict; `null` when nothing fired.
    pub confidence: Option<f64>,
    /// One-line operator-facing explanation.
    pub summary: String,
    /// Every signal that fired, across all layers.
    pub findings: Vec<Finding>,
    /// Per-layer accounting for the layers that answered.
    pub layer_results: Vec<LayerOutcome>,
    /// Whether at least one configured layer failed to answer.
    pub degraded: bool,
    /// The layers that dropped out, empty when coverage was complete.
    pub layers_failed: Vec<LayerFailure>,
    /// Whether the input exceeded the engine's byte cap and was cut.
    pub input_truncated: bool,
    /// Input bytes actually inspected.
    pub input_bytes_scanned: u64,
    /// Engine build that produced this result.
    pub engine_version: String,
    /// Detection-pipeline duration.
    ///
    /// Engine construction is not included: the daemon builds scanners
    /// outside the request path, so there is no per-request init cost to
    /// report the way the V1 command line did.
    pub scan_ms: f64,
    /// Mode the scan actually ran in, echoed for correlation.
    pub mode: ScanMode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_level_is_a_total_injective_projection_of_the_verdict() {
        // Every verdict grades, and no two verdicts collapse onto one grade;
        // otherwise `riskLevel` would lose information the verdict carries.
        let grades = [Verdict::Pass, Verdict::Warn, Verdict::Deny].map(RiskLevel::from);
        assert_eq!(grades, [RiskLevel::Low, RiskLevel::Medium, RiskLevel::High]);
    }

    #[test]
    fn mode_capabilities_match_the_layers_each_mode_runs() {
        assert!(ScanMode::MultiTurn.is_conversational());
        assert!(!ScanMode::Standard.is_conversational());
        assert!(ScanMode::Standard.uses_selectable_model());
        assert!(ScanMode::Strict.uses_selectable_model());
        // `fast` has no model layer and `multi_turn` uses its own judge, so
        // neither exposes the selectable classifier.
        assert!(!ScanMode::Fast.uses_selectable_model());
        assert!(!ScanMode::MultiTurn.uses_selectable_model());
    }
}
