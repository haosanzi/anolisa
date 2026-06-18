"""Multi-turn intent classifier (L4) — prompt formatting and classification.

Fine-tuned Qwen3-4B-Instruct checkpoint (TurnGate) that classifies whether
an assistant response is harmful given the full conversation context.  Emits a
single digit token (``"0"`` = harmful → BLOCK, ``"1"`` = benign → PASS).

Architecture:
- The 4B model is served by a system-level **Ollama** instance.
- This module formats the prompt and calls Ollama's ``/api/chat`` endpoint.
- No local model loading — daemon stays lightweight.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Ollama service configuration (environment variables)
# ---------------------------------------------------------------------------

_OLLAMA_BASE_URL_ENV = "AGENT_SEC_OLLAMA_BASE_URL"
_OLLAMA_MODEL_ENV = "AGENT_SEC_OLLAMA_MODEL"
_OLLAMA_TIMEOUT_ENV = "AGENT_SEC_OLLAMA_TIMEOUT_SECONDS"

_DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
_DEFAULT_OLLAMA_MODEL = "turngate"
_DEFAULT_OLLAMA_TIMEOUT = 30  # seconds


# ---------------------------------------------------------------------------
# Qwen3 chat template tokens (for raw mode in Ollama)
# ---------------------------------------------------------------------------
# The TurnGate model was fine-tuned with Qwen3's chat template applied.
# When using Ollama raw mode, we must wrap the prompt manually.
_CHAT_TEMPLATE_PREFIX = "<|im_start|>user\n"
_CHAT_TEMPLATE_SUFFIX = "<|im_end|>\n<|im_start|>assistant\n"


# ---------------------------------------------------------------------------
# Prompt template (mirrors TurnGate RLDefender training format)
# ---------------------------------------------------------------------------

NAIVE_PROMPT_TEMPLATE_WITH_RESPONSE = """Determine if the following AI assistant response is harmful (violating safety guidelines) or benign (safe and helpful).

Conversation:
{history}
USER: {question}
ASSISTANT: {assistant_response}

Is the final ASSISTANT response harmful? Answer 0 for harmful, 1 for benign:"""


def _get_ollama_config() -> tuple[str, str, int]:
    """Return (base_url, model_name, timeout_seconds) from env or defaults."""
    base_url = os.environ.get(_OLLAMA_BASE_URL_ENV, _DEFAULT_OLLAMA_BASE_URL).rstrip("/")
    model = os.environ.get(_OLLAMA_MODEL_ENV, _DEFAULT_OLLAMA_MODEL)
    try:
        timeout = int(os.environ.get(_OLLAMA_TIMEOUT_ENV, str(_DEFAULT_OLLAMA_TIMEOUT)))
    except ValueError:
        timeout = _DEFAULT_OLLAMA_TIMEOUT
    return base_url, model, timeout


def format_history(history: list[dict]) -> str:
    """Format prior turns into the ``USER: ...`` / ``ASSISTANT: ...`` block.

    Mirrors ``_format_history_for_prompt`` in ``TurnGate/src/defender.py``.
    Empty history collapses to a placeholder string so the template still renders.

    Accepts two formats:
    - Canonical dict format: ``[{"role": "user", "content": "..."}]``
    - Legacy string format: ``["user: ...", "assistant: ..."]``
    """
    if not history:
        return "(No previous turns)"
    lines: list[str] = []
    for turn in history:
        if isinstance(turn, dict):
            role = str(turn.get("role", "unknown")).upper()
            content = turn.get("content", "")
            lines.append(f"{role}: {content}")
        elif isinstance(turn, str):
            # Legacy format: "user: ..." or "assistant: ..."
            lines.append(turn.upper() if ": " not in turn else turn)
        else:
            lines.append(f"UNKNOWN: {turn}")
    return "\n\n".join(lines)


def format_defender_prompt(
    history: list[dict],
    current_query: str,
    assistant_response: str,
) -> str:
    """Format the user-content payload that gets wrapped in the chat template.

    Returns the full template-substituted string; the caller is expected to
    wrap it as ``[{"role": "user", "content": <result>}]`` and pass through
    ``tokenizer.apply_chat_template``.
    """
    return NAIVE_PROMPT_TEMPLATE_WITH_RESPONSE.format(
        history=format_history(history),
        question=current_query,
        assistant_response=assistant_response,
    )


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

_DEFAULT_HARMFUL_THRESHOLD = 0.55


class MultiIntentClassifier:
    """Multi-turn intent classifier calling Ollama for inference.

    Sends the formatted safety-classification prompt to Ollama's
    ``/api/chat`` endpoint and parses the single-digit response
    (``"0"`` = harmful, ``"1"`` = benign).

    The 4B model runs in a system-level Ollama process; this class
    only does HTTP and response parsing — no local GPU memory needed.
    """

    def __init__(
        self,
        harmful_threshold: float = _DEFAULT_HARMFUL_THRESHOLD,
    ) -> None:
        self._harmful_threshold = harmful_threshold
        self._base_url: str | None = None
        self._model: str | None = None
        self._timeout: int | None = None

    def _ensure_config(self) -> tuple[str, str, int]:
        """Lazily resolve config so env vars can be set after import."""
        if self._base_url is None:
            self._base_url, self._model, self._timeout = _get_ollama_config()
        return self._base_url, self._model, self._timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def warmup(self) -> None:
        """Verify Ollama is reachable and the model is available.

        Sends a lightweight request to Ollama to confirm connectivity.
        No local model loading — the 4B model lives in the Ollama process.
        """
        base_url, model, timeout = self._ensure_config()
        # List local models to verify the target model exists
        try:
            req = urllib.request.Request(
                f"{base_url}/api/tags",
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
                model_names = [m.get("name", "") for m in data.get("models", [])]
                # Ollama model names can include :tag, check prefix match
                found = any(model in name or name.startswith(model) for name in model_names)
                if found:
                    log.info(
                        "Ollama model '%s' verified (url=%s).",
                        model,
                        base_url,
                    )
                else:
                    log.warning(
                        "Ollama reachable but model '%s' not found in: %s",
                        model,
                        model_names,
                    )
        except Exception as exc:
            log.warning("Ollama warmup failed (url=%s): %s", base_url, exc)

    def classify(
        self,
        history: list[dict],
        current_query: str,
        assistant_response: str,
    ) -> dict[str, Any]:
        """Classify one (history, query, response) triple via Ollama.

        Uses ``/api/generate`` with ``raw=true`` to bypass Qwen3's thinking
        mode and get a fast completion-style response.

        Returns a dict with ``verdict`` (``"block"`` / ``"pass"``),
        ``raw_token``, ``p_harmful``, and ``latency_ms``.

        Raises:
            RuntimeError: if Ollama is unreachable or returns an error.
        """
        base_url, model, timeout = self._ensure_config()
        prompt_body = format_defender_prompt(history, current_query, assistant_response)
        # Wrap with Qwen3 chat template so model sees its trained format
        prompt = f"{_CHAT_TEMPLATE_PREFIX}{prompt_body}{_CHAT_TEMPLATE_SUFFIX}"

        payload = json.dumps({
            "model": model,
            "prompt": prompt,
            "stream": False,
            "raw": True,
            "logprobs": True,
            "top_logprobs": 10,
            "options": {
                "num_predict": 1,  # only need first token logprobs
                "temperature": 0,
            },
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read())
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Ollama request failed (url={base_url}): {exc}"
            ) from exc
        except Exception as exc:
            raise RuntimeError(
                f"Ollama request error: {exc}"
            ) from exc

        latency_ms = (time.perf_counter() - t0) * 1000

        # Extract logprobs of tokens "0" and "1" and apply softmax.
        # This mirrors the local torch approach: compare logits of token_id_0
        # vs token_id_1, then softmax to get p_harmful.
        logprob_0: float | None = None
        logprob_1: float | None = None

        logprobs_list = body.get("logprobs") or []
        if logprobs_list:
            top_lps = logprobs_list[0].get("top_logprobs") or []
            for entry in top_lps:
                if entry["token"] == "0":
                    logprob_0 = entry["logprob"]
                elif entry["token"] == "1":
                    logprob_1 = entry["logprob"]

        if logprob_0 is not None and logprob_1 is not None:
            # Softmax over just the two classes
            import math
            max_lp = max(logprob_0, logprob_1)
            exp_0 = math.exp(logprob_0 - max_lp)
            exp_1 = math.exp(logprob_1 - max_lp)
            p_harmful = exp_0 / (exp_0 + exp_1)
        else:
            # Fallback: parse generated text
            raw_text = body.get("response", "").strip()
            raw_token = raw_text[:1] if raw_text else ""
            if raw_token == "0":
                p_harmful = 0.95
            elif raw_token == "1":
                p_harmful = 0.05
            else:
                log.warning(
                    "Ollama: no logprobs for 0/1 and unexpected token: %r",
                    raw_text[:100],
                )
                p_harmful = 0.5

        verdict = "block" if p_harmful > 0.50 else "pass"
        raw_text = body.get("response", "").strip()

        return {
            "verdict": verdict,
            "raw_token": raw_text[:1] if raw_text else "",
            "raw_text": raw_text,
            "p_harmful": round(p_harmful, 4),
            "latency_ms": round(latency_ms, 2),
        }

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def model_name(self) -> str:
        _, model, _ = self._ensure_config()
        return model

    @property
    def is_loaded(self) -> bool:
        """Always True — model lives in Ollama, not in this process."""
        return True
