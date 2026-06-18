"""L4 multi-turn intent detector — calls Ollama-hosted TurnGate model via HTTP.

The 4B intent model runs in a system-level Ollama process.  This detector
formats the request and delegates to MultiIntentClassifier which handles
the HTTP call.  No local GPU memory is used by the daemon.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from agent_sec_cli.prompt_scanner.detectors.base import DetectionLayer
from agent_sec_cli.prompt_scanner.models.multi_intent import MultiIntentClassifier
from agent_sec_cli.prompt_scanner.result import (
    LayerResult,
    ThreatDetail,
)

log = logging.getLogger(__name__)

# Metadata keys the scanner injects when running INTENT_CHAIN.
META_HISTORY = "conversation_history"
META_ASSISTANT_RESPONSE = "assistant_response"


class MultiTurnIntentDetector(DetectionLayer):
    """L4 detector that classifies a (history, query, response) triple.

    ``detect`` expects ``metadata[META_HISTORY]`` and
    ``metadata[META_ASSISTANT_RESPONSE]`` to be set; the scanner's
    ``scan_conversation`` method takes care of that.  Single-turn callers
    that go through the regular ``scan`` API will simply see a passthrough
    ``LayerResult`` — the layer never blocks when context is missing.

    The intent model is hosted by Ollama; this detector only makes HTTP
    calls via MultiIntentClassifier — no local model loading.
    """

    def __init__(self) -> None:
        self._classifier: MultiIntentClassifier | None = None

    @property
    def name(self) -> str:
        return "multi_turn_intent"

    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        # Always advertise as available: the classifier is lazily loaded,
        # and we want the layer to register so INTENT_CHAIN mode can run.
        return True

    def warmup(self) -> None:
        """Pre-load the intent classifier model to eliminate cold-start latency."""
        self._get_classifier().warmup()

    # ------------------------------------------------------------------

    def detect(self, text: str, metadata: dict[str, Any] | None = None) -> LayerResult:
        meta = metadata or {}
        history = meta.get(META_HISTORY)
        assistant_response = meta.get(META_ASSISTANT_RESPONSE)

        if not isinstance(history, list) or assistant_response is None:
            return self._passthrough(reason="missing_conversation_context")

        t0 = time.perf_counter()

        try:
            classifier = self._get_classifier()
            response = classifier.classify(
                history=history,
                current_query=text,
                assistant_response=str(assistant_response),
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("Intent classifier call failed: %s", exc)
            return self._passthrough(
                reason=f"classifier_error:{type(exc).__name__}",
                latency_ms=(time.perf_counter() - t0) * 1000,
            )

        latency_ms = (time.perf_counter() - t0) * 1000
        verdict = response.get("verdict", "pass")

        if verdict == "block":
            details = [
                ThreatDetail(
                    rule_id="L4-INTENT-CHAIN",
                    description=(
                        "Multi-turn intent classifier flagged the assistant response "
                        "as harmful given the conversation history."
                    ),
                    matched_text=text[:200],
                    category="jailbreak",
                )
            ]
            return LayerResult(
                layer_name=self.name,
                detected=True,
                score=response.get("p_harmful", 0.95),
                details=details,
                latency_ms=latency_ms,
            )

        return LayerResult(
            layer_name=self.name,
            detected=False,
            score=0.0,
            details=[],
            latency_ms=latency_ms,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _get_classifier(self) -> MultiIntentClassifier:
        """Return the shared MultiIntentClassifier instance (lazy-init)."""
        if self._classifier is None:
            self._classifier = MultiIntentClassifier()
        return self._classifier

    @staticmethod
    def _passthrough(*, reason: str, latency_ms: float = 0.0) -> LayerResult:
        log.debug("multi_turn_intent passthrough: %s", reason)
        return LayerResult(
            layer_name="multi_turn_intent",
            detected=False,
            score=0.0,
            details=[],
            latency_ms=latency_ms,
        )
