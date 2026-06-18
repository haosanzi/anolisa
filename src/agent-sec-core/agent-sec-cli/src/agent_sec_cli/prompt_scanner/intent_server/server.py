"""HTTP server exposing the intent classifier on localhost.

stdlib-only (``http.server`` + ``ThreadingHTTPServer``) so the sidecar
adds no new dependencies.  One classifier instance is shared across
worker threads, with internal locking inside ``IntentClassifier``.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from agent_sec_cli.prompt_scanner.intent_server.inference import IntentClassifier
from agent_sec_cli.prompt_scanner.intent_server.paths import (
    LOG_FILE,
    PID_FILE,
    PORT_FILE,
    is_pid_alive,
    read_pid,
)

log = logging.getLogger(__name__)


# Module-level singletons shared by the request handler.
_CLASSIFIER: IntentClassifier | None = None
_LAST_REQUEST_AT: float = 0.0
_IDLE_TIMEOUT_SECONDS: float = 1800.0
_SHUTDOWN_EVENT = threading.Event()


def _touch() -> None:
    global _LAST_REQUEST_AT
    _LAST_REQUEST_AT = time.monotonic()


class _Handler(BaseHTTPRequestHandler):
    """Tiny request router for ``GET /health`` and ``POST /classify``."""

    server_version = "IntentServer/0.1"

    # Silence default per-request stderr logging.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        log.debug("%s - %s", self.address_string(), format % args)

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 (stdlib API)
        if self.path == "/health":
            self._respond_json(
                HTTPStatus.OK,
                {
                    "status": "ready" if _CLASSIFIER and _CLASSIFIER.is_loaded else "loading",
                    "model_path": str(_CLASSIFIER.model_dir) if _CLASSIFIER else None,
                    "device": _CLASSIFIER.device if _CLASSIFIER else None,
                    "idle_seconds": round(time.monotonic() - _LAST_REQUEST_AT, 1),
                },
            )
            _touch()
            return
        self._respond_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/classify":
            self._respond_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 1_048_576:  # 1 MiB cap
            self._respond_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "missing or oversized body"},
            )
            return
        try:
            body = self.rfile.read(length).decode("utf-8")
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._respond_json(
                HTTPStatus.BAD_REQUEST,
                {"error": f"invalid JSON: {exc}"},
            )
            return

        history = payload.get("history") or []
        current_query = payload.get("current_query") or ""
        assistant_response = payload.get("assistant_response") or ""

        if not isinstance(history, list) or not isinstance(current_query, str):
            self._respond_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "history must be a list and current_query a string"},
            )
            return

        try:
            assert _CLASSIFIER is not None
            result = _CLASSIFIER.classify(history, current_query, assistant_response)
        except Exception as exc:  # noqa: BLE001 (server boundary)
            log.exception("Classification failed")
            self._respond_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": f"classification failed: {exc}"},
            )
            return

        _touch()
        self._respond_json(HTTPStatus.OK, result)

    # ------------------------------------------------------------------

    def _respond_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _idle_watchdog(stop_event: threading.Event) -> None:
    """Background thread that shuts the server down after long idle."""
    while not stop_event.wait(timeout=60.0):
        idle = time.monotonic() - _LAST_REQUEST_AT
        if idle > _IDLE_TIMEOUT_SECONDS:
            log.info(
                "Idle for %.0fs (>%.0fs), shutting down",
                idle,
                _IDLE_TIMEOUT_SECONDS,
            )
            _SHUTDOWN_EVENT.set()
            return


def _write_pid_port(pid: int, port: int) -> None:
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(pid))
    PORT_FILE.write_text(str(port))


def _cleanup_pid_port() -> None:
    for path in (PID_FILE, PORT_FILE):
        try:
            if path.exists():
                path.unlink()
        except OSError:
            pass


def _another_instance_running() -> bool:
    pid = read_pid()
    return pid is not None and is_pid_alive(pid)


def serve_forever(
    *,
    model_dir: Path | None = None,
    port: int = 0,
    idle_timeout_seconds: float = 1800.0,
) -> None:
    """Run the sidecar HTTP server.  Blocks until shutdown.

    Args:
        model_dir: Override the default checkpoint location.
        port: Port to bind on 127.0.0.1.  ``0`` requests a kernel-assigned
            ephemeral port.
        idle_timeout_seconds: Server self-terminates after this many seconds
            without any request arriving.
    """
    global _CLASSIFIER, _IDLE_TIMEOUT_SECONDS

    if _another_instance_running():
        log.error("Another intent-server is already running (PID %s); exiting.", read_pid())
        sys.exit(1)

    _IDLE_TIMEOUT_SECONDS = idle_timeout_seconds
    _CLASSIFIER = IntentClassifier(model_dir=model_dir)
    # Eager load so /health reports "ready" once it accepts traffic.
    _CLASSIFIER.load()

    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    bound_port = server.server_address[1]
    _write_pid_port(os.getpid(), bound_port)
    log.info("Intent server listening on 127.0.0.1:%d", bound_port)

    _touch()
    watchdog_thread = threading.Thread(
        target=_idle_watchdog, args=(_SHUTDOWN_EVENT,), daemon=True
    )
    watchdog_thread.start()

    def _on_signal(signum: int, _frame: Any) -> None:
        log.info("Received signal %d, shutting down", signum)
        _SHUTDOWN_EVENT.set()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        _SHUTDOWN_EVENT.wait()
    finally:
        log.info("Stopping HTTP server")
        server.shutdown()
        server.server_close()
        _cleanup_pid_port()


def healthcheck(port: int, timeout: float = 1.0) -> bool:
    """Quick TCP probe used by the CLI ``status`` command."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def configure_logging(verbose: bool = False) -> None:
    """Send sidecar logs to ``LOG_FILE``.  Idempotent."""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
