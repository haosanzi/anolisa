"""Long-running TurnGate intent classifier sidecar.

Loads the fine-tuned Qwen3-4B multi-turn intent classifier once, then exposes
a small HTTP API on localhost so the L4 detector and demo scripts can issue
classification requests without paying the model-load cost on every call.
"""

from agent_sec_cli.prompt_scanner.intent_server._format import (
    NAIVE_PROMPT_TEMPLATE_WITH_RESPONSE,
    format_defender_prompt,
    format_history,
)
from agent_sec_cli.prompt_scanner.intent_server.paths import (
    DEFAULT_MODEL_PATH,
    LOG_FILE,
    PID_FILE,
    PORT_FILE,
    read_port,
)

__all__ = [
    "NAIVE_PROMPT_TEMPLATE_WITH_RESPONSE",
    "format_defender_prompt",
    "format_history",
    "DEFAULT_MODEL_PATH",
    "PID_FILE",
    "PORT_FILE",
    "LOG_FILE",
    "read_port",
]
