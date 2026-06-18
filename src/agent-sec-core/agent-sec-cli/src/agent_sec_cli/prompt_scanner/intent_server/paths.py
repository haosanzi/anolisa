"""Filesystem locations used by the intent-server sidecar.

Centralised so the detector, CLI and server agree on where the PID, port
and log files live.
"""

import os
from pathlib import Path

# Default checkpoint directory.  Mirrors the path the user trains and
# downloads to.  Override at runtime via the
# ``PROMPT_SCANNER_INTENT_MODEL_PATH`` environment variable.
DEFAULT_MODEL_PATH = (
    Path.home() / ".cache" / "prompt_scanner" / "models" / "TurnGate" / "Qwen3-4B" / "rl_v4_best"
)

_RUNTIME_DIR = Path.home() / ".cache" / "prompt_scanner"
PID_FILE = _RUNTIME_DIR / "intent-server.pid"
PORT_FILE = _RUNTIME_DIR / "intent-server.port"
LOG_FILE = _RUNTIME_DIR / "intent-server.log"


def model_path() -> Path:
    """Return the configured model path, honoring env override."""
    override = os.environ.get("PROMPT_SCANNER_INTENT_MODEL_PATH")
    if override:
        return Path(override).expanduser()
    return DEFAULT_MODEL_PATH


def read_port() -> int | None:
    """Return the port number written by a running sidecar, or ``None``."""
    try:
        raw = PORT_FILE.read_text().strip()
    except OSError:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def read_pid() -> int | None:
    """Return the PID of a running sidecar, or ``None``."""
    try:
        raw = PID_FILE.read_text().strip()
    except OSError:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def is_pid_alive(pid: int) -> bool:
    """Return True if a process with this PID currently exists."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but is owned by another user; assume alive.
        return True
    except OSError:
        return False
    return True
