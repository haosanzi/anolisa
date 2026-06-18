"""prompt_scan backend — delegates to the prompt_scanner package."""

import json
from typing import Any

from agent_sec_cli.prompt_scanner.config import ScanMode
from agent_sec_cli.prompt_scanner.result import Verdict
from agent_sec_cli.prompt_scanner.scanner import PromptScanner
from agent_sec_cli.security_middleware.backends.base import BaseBackend
from agent_sec_cli.security_middleware.context import RequestContext
from agent_sec_cli.security_middleware.result import ActionResult


class PromptScanBackend(BaseBackend):
    """Scan prompt text for injection / jailbreak attempts using the prompt_scanner engine.

    Two call shapes:

    1. Single-turn (default): ``invoke("prompt_scan", text=..., mode=..., source=...)``
       runs the configured detector chain over a lone prompt.
    2. Multi-turn (INTENT_CHAIN): pass ``history=`` and ``assistant_response=``
       in addition to ``text``.  The text is treated as the *current* user
       query and routed through ``scanner.scan_conversation`` so the L4
       multi-turn intent detector receives the full triple.
    """

    def execute(self, ctx: RequestContext, **kwargs: Any) -> ActionResult:
        text: str = kwargs.get("text", "")
        mode_arg = kwargs.get("mode", "standard")
        source: str = kwargs.get("source", "")
        history = kwargs.get("history")
        assistant_response = kwargs.get("assistant_response")

        if not text or not text.strip():
            return ActionResult(
                success=False,
                error="prompt_scan error: no input text provided",
                exit_code=1,
            )

        try:
            scan_mode = (
                mode_arg if isinstance(mode_arg, ScanMode) else ScanMode(str(mode_arg).lower())
            )
        except ValueError:
            return ActionResult(
                success=False,
                error=(
                    f"prompt_scan error: invalid mode '{mode_arg}'. "
                    "Choose from: fast, standard, strict, intent_chain"
                ),
                exit_code=1,
            )

        try:
            scanner = PromptScanner(mode=scan_mode)
            result = scanner.scan(text, source=source if source else None)
        except Exception as exc:
            return _scanner_error_result(f"Scanner error: {exc}")
        scanner = PromptScanner(mode=scan_mode)
        if history is not None or assistant_response is not None:
            result = scanner.scan_conversation(
                history=history if isinstance(history, list) else [],
                current_query=text,
                assistant_response=assistant_response or "",
                source=source if source else None,
            )
        else:
            result = scanner.scan(text, source=source if source else None)

        has_error = result.verdict == Verdict.ERROR
        d = result.to_dict()

        return ActionResult(
            success=not has_error,
            data=d,
            stdout=json.dumps(d, indent=2, ensure_ascii=False),
            exit_code=1 if has_error else 0,
        )


def _scanner_error_result(message: str) -> ActionResult:
    data = {
        "schema_version": "1.0",
        "ok": False,
        "verdict": Verdict.ERROR.value,
        "risk_level": "unknown",
        "threat_type": "unknown",
        "confidence": 0.0,
        "summary": message,
        "findings": [],
        "layer_results": [],
        "engine_version": "0.1.0",
        "elapsed_ms": 0,
    }
    return ActionResult(
        success=False,
        data=data,
        stdout=json.dumps(data, indent=2, ensure_ascii=False),
        error=message,
        exit_code=1,
    )
