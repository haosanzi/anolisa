"""``python -m agent_sec_cli.prompt_scanner.intent_server`` entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent_sec_cli.prompt_scanner.intent_server.paths import model_path
from agent_sec_cli.prompt_scanner.intent_server.server import (
    configure_logging,
    serve_forever,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-sec-intent-server",
        description="Long-running TurnGate intent classifier sidecar.",
    )
    parser.add_argument(
        "--model-path",
        type=Path,
        default=None,
        help="Override checkpoint directory (defaults to PROMPT_SCANNER_INTENT_MODEL_PATH "
        "or ~/.cache/prompt_scanner/models/TurnGate/Qwen3-4B/rl_v4_best).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="Port to bind on 127.0.0.1.  0 (default) uses an ephemeral port.",
    )
    parser.add_argument(
        "--idle-timeout",
        type=float,
        default=1800.0,
        help="Self-terminate after this many seconds of inactivity (default 1800).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    args = parser.parse_args(argv)

    configure_logging(verbose=args.verbose)
    resolved = args.model_path or model_path()
    serve_forever(
        model_dir=resolved,
        port=args.port,
        idle_timeout_seconds=args.idle_timeout,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
