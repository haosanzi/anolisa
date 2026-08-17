#!/usr/bin/env agent-sec-python
"""Container health probe for agent-sec-daemon."""

import argparse
import sys
from typing import Any

from agent_sec_cli.daemon.client import DaemonClient


def _healthy_snapshot(data: Any, require_model: bool) -> bool:
    if not isinstance(data, dict) or data.get("status") != "ok":
        return False
    if not require_model:
        return True

    prompt_scan = data.get("prompt_scan")
    return (
        isinstance(prompt_scan, dict)
        and prompt_scan.get("status") == "ready"
        and prompt_scan.get("loaded") is True
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-model",
        action="store_true",
        help="also require the prompt scanner model to be loaded",
    )
    args = parser.parse_args()

    try:
        response = DaemonClient(timeout_ms=1000).call(
            "daemon.health",
            trace_context={},
            timeout_ms=1000,
            caller="container-health",
        )
    except Exception as exc:
        print(f"agent-sec-daemon health request failed: {exc}", file=sys.stderr)
        return 1

    if not response.ok or not _healthy_snapshot(response.data, args.require_model):
        print("agent-sec-daemon reported an unhealthy state", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
