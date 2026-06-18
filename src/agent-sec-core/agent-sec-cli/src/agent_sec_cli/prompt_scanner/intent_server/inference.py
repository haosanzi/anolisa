"""TurnGate intent classifier — model loading + single-turn classification.

The fine-tuned Qwen3-4B-Instruct checkpoint emits a single digit token
(``"0"`` for harmful → BLOCK, ``"1"`` for benign → PASS).  We greedy-decode
two new tokens and parse the first digit, matching the parsing logic in
``TurnGate/src/defender.py:NaiveLLMDefender.predict_batch``.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any

from agent_sec_cli.prompt_scanner.intent_server._format import format_defender_prompt
from agent_sec_cli.prompt_scanner.intent_server.paths import model_path

log = logging.getLogger(__name__)


_DEFAULT_HARMFUL_THRESHOLD = 0.55


def _parse_first_digit(text: str) -> str | None:
    """Return ``"0"`` or ``"1"`` if found, else ``None``."""
    for ch in text:
        if ch in ("0", "1"):
            return ch
    return None


class IntentClassifier:
    """Wraps tokenizer + model + logit-based verdict.

    Instead of greedy-decoding a digit and trusting it blindly, we read the
    logits at the first generated-token position and compute
    ``P("0") / (P("0") + P("1"))``.  The sample is classified as harmful
    only when this probability exceeds ``harmful_threshold`` (default 0.55).
    This cuts false-positive rate roughly in half compared to the naive
    greedy approach (0.50 threshold) while retaining most of the TPR gain
    from RL fine-tuning.
    """

    def __init__(
        self,
        model_dir: Path | None = None,
        harmful_threshold: float = _DEFAULT_HARMFUL_THRESHOLD,
    ) -> None:
        self._model_dir = Path(model_dir) if model_dir else model_path()
        self._harmful_threshold = harmful_threshold
        self._lock = threading.Lock()
        self._tokenizer = None
        self._model = None
        self._device: str | None = None
        self._token_id_0: int | None = None
        self._token_id_1: int | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Eagerly load tokenizer + model.

        Idempotent: subsequent calls are a no-op.  Heavy — the 4B model
        needs ~30-60s on a warm cache.
        """
        with self._lock:
            if self._model is not None:
                return
            self._do_load()

    def _do_load(self) -> None:
        # Lazy imports so the package can be inspected without torch installed.
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        if not self._model_dir.exists():
            raise FileNotFoundError(
                f"Intent classifier model not found at {self._model_dir}. "
                "Either set PROMPT_SCANNER_INTENT_MODEL_PATH or place the "
                "checkpoint at the default location."
            )

        if torch.cuda.is_available():
            device = "cuda"
            dtype = torch.float16
        elif torch.backends.mps.is_available():
            device = "mps"
            dtype = torch.float16
        else:
            device = "cpu"
            dtype = torch.float32

        log.info(
            "Loading intent classifier from %s onto %s (dtype=%s)",
            self._model_dir,
            device,
            dtype,
        )
        t0 = time.perf_counter()

        tokenizer = AutoTokenizer.from_pretrained(str(self._model_dir))
        model = AutoModelForCausalLM.from_pretrained(
            str(self._model_dir),
            torch_dtype=dtype,
            low_cpu_mem_usage=True,
        )
        model.to(torch.device(device))
        model.eval()

        self._tokenizer = tokenizer
        self._model = model
        self._device = device
        self._token_id_0 = tokenizer.encode("0", add_special_tokens=False)[0]
        self._token_id_1 = tokenizer.encode("1", add_special_tokens=False)[0]
        log.info("Intent classifier ready in %.1fs", time.perf_counter() - t0)

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def classify(
        self,
        history: list[dict],
        current_query: str,
        assistant_response: str,
    ) -> dict[str, Any]:
        """Classify one (history, query, response) triple.

        Returns a dict with ``verdict`` (``"block"`` / ``"pass"``),
        ``raw_token`` (the greedy first digit, or ``None``),
        ``p_harmful`` (softmax probability of token ``"0"``),
        and ``latency_ms``.
        """
        self.load()

        import torch

        prompt = format_defender_prompt(history, current_query, assistant_response)

        with self._lock:
            t0 = time.perf_counter()
            messages = [{"role": "user", "content": prompt}]
            encoded = self._tokenizer.apply_chat_template(
                messages,
                tokenize=True,
                add_generation_prompt=True,
                return_tensors="pt",
                return_dict=True,
            )
            input_ids = encoded["input_ids"].to(self._model.device)
            attention_mask = encoded.get("attention_mask")
            if attention_mask is not None:
                attention_mask = attention_mask.to(self._model.device)

            with torch.inference_mode():
                outputs = self._model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                )
                logits = outputs.logits[0, -1, :]
                logit_0 = logits[self._token_id_0].float()
                logit_1 = logits[self._token_id_1].float()
                probs = torch.softmax(torch.stack([logit_0, logit_1]), dim=0)
                p_harmful = probs[0].item()

            latency_ms = (time.perf_counter() - t0) * 1000

        raw_token = "0" if p_harmful > 0.5 else "1"
        if p_harmful > self._harmful_threshold:
            verdict = "block"
        else:
            verdict = "pass"

        return {
            "verdict": verdict,
            "raw_token": raw_token,
            "raw_text": raw_token,
            "p_harmful": round(p_harmful, 4),
            "latency_ms": round(latency_ms, 2),
        }

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    @property
    def model_dir(self) -> Path:
        return self._model_dir

    @property
    def device(self) -> str | None:
        return self._device

    @property
    def is_loaded(self) -> bool:
        return self._model is not None
