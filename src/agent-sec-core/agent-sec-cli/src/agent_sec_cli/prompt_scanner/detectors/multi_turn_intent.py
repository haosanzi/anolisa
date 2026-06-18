"""L4 multi-turn intent detector — talks to the intent-server sidecar.

The detector itself is intentionally thin: format the request, POST it to
the locally-bound sidecar, translate the JSON response into a
``LayerResult``.  The heavy work (model load, generation) lives in
:mod:`agent_sec_cli.prompt_scanner.intent_server`.

When the sidecar is not running we attempt to spawn it once (detached) and
return a fail-open ``LayerResult``; the next scan will succeed once the
model has loaded.  This mirrors the warmup flow used by L2.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any

from agent_sec_cli.prompt_scanner.detectors.base import DetectionLayer
from agent_sec_cli.prompt_scanner.intent_server.paths import (
    PORT_FILE,
    is_pid_alive,
    model_path,
    read_pid,
    read_port,
)
from agent_sec_cli.prompt_scanner.result import (
    LayerResult,
    ThreatDetail,
)

log = logging.getLogger(__name__)

# Metadata keys the scanner injects when running INTENT_CHAIN.
META_HISTORY = "conversation_history"
META_ASSISTANT_RESPONSE = "assistant_response"

# Connect / read timeouts when calling the sidecar.
_CONNECT_TIMEOUT_SECONDS = 1.0
_REQUEST_TIMEOUT_SECONDS = 8.0


class MultiTurnIntentDetector(DetectionLayer):
    """L4 detector that classifies a (history, query, response) triple.

    ``detect`` expects ``metadata[META_HISTORY]`` and
    ``metadata[META_ASSISTANT_RESPONSE]`` to be set; the scanner's
    ``scan_conversation`` method takes care of that.  Single-turn callers
    that go through the regular ``scan`` API will simply see a passthrough
    ``LayerResult`` — the layer never blocks when context is missing.
    """

    @property
    def name(self) -> str:
        return "multi_turn_intent"

    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        # Always advertise as available: the sidecar is lazily spawned,
        # and we want the layer to register so INTENT_CHAIN mode can run.
        return True

    def warmup(self) -> None:
        """Pre-spawn the sidecar so the first detect() call is fast."""
        if not model_path().exists():
            log.warning(
                "Intent classifier checkpoint missing at %s; skipping warmup. "
                "Place the trained model there before using INTENT_CHAIN mode.",
                model_path(),
            )
            return
        if self._sidecar_alive():
            return
        self._spawn_sidecar()

    # ------------------------------------------------------------------

    def detect(self, text: str, metadata: dict[str, Any] | None = None) -> LayerResult:
        meta = metadata or {}
        history = meta.get(META_HISTORY)
        assistant_response = meta.get(META_ASSISTANT_RESPONSE)

        if not isinstance(history, list) or assistant_response is None:
            return self._passthrough(reason="missing_conversation_context")

        t0 = time.perf_counter()
        port = read_port()
        if port is None or not self._port_open(port):
            self._spawn_sidecar()
            return self._passthrough(
                reason="sidecar_starting",
                latency_ms=(time.perf_counter() - t0) * 1000,
            )

        try:
            response = self._post_classify(
                port,
                history=history,
                current_query=text,
                assistant_response=str(assistant_response),
            )
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            log.warning("intent-server call failed: %s", exc)
            return self._passthrough(
                reason=f"sidecar_error:{type(exc).__name__}",
                latency_ms=(time.perf_counter() - t0) * 1000,
            )

        latency_ms = (time.perf_counter() - t0) * 1000
        verdict = response.get("verdict", "pass")
        raw_token = response.get("raw_token")

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
                # Single-token classifier: confidence isn't exposed.  Use 0.95
                # as a stand-in so the scanner can still surface a number.
                score=0.95,
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

    @staticmethod
    def _port_open(port: int) -> bool:
        try:
            with socket.create_connection(
                ("127.0.0.1", port), timeout=_CONNECT_TIMEOUT_SECONDS
            ):
                return True
        except OSError:
            return False

    def _sidecar_alive(self) -> bool:
        port = read_port()
        if port is None or not PORT_FILE.exists():
            return False
        pid = read_pid()
        if pid is None or not is_pid_alive(pid):
            return False
        return self._port_open(port)

    @staticmethod
    def _post_classify(
        port: int,
        *,
        history: list,
        current_query: str,
        assistant_response: str,
    ) -> dict[str, Any]:
        payload = json.dumps(
            {
                "history": history,
                "current_query": current_query,
                "assistant_response": assistant_response,
            },
            ensure_ascii=False,
        ).encode("utf-8")
        req = urllib.request.Request(  # noqa: S310 (loopback only)
            f"http://127.0.0.1:{port}/classify",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(  # noqa: S310 (loopback only)
            req, timeout=_REQUEST_TIMEOUT_SECONDS
        ) as resp:
            body = resp.read().decode("utf-8")
        return json.loads(body)

    @staticmethod
    def _spawn_sidecar() -> None:
        """Launch the sidecar in a detached child process.

        Best-effort: failures are logged and ignored — the next scan will
        try again.  We use ``python -m agent_sec_cli.prompt_scanner.intent_server``
        instead of the ``agent-sec-cli`` console-script so the spawn works
        even when the package is being run from a checkout.
        """
        if not model_path().exists():
            log.warning(
                "Cannot start intent-server: checkpoint missing at %s",
                model_path(),
            )
            return

        cmd = [sys.executable, "-m", "agent_sec_cli.prompt_scanner.intent_server"]
        log.info("Spawning intent-server sidecar: %s", " ".join(cmd))
        try:
            subprocess.Popen(  # noqa: S603 (trusted args)
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
                # Keep the spawned server alive after the parent exits.
                env=os.environ.copy(),
            )
        except OSError as exc:
            log.warning("Failed to spawn intent-server: %s", exc)
