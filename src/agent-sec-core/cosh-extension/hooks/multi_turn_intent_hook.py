#!/usr/bin/env python3
"""Cosh hook script for the L4 multi-turn intent classifier.

Hook point: **AfterModel** — fires once the LLM produces a response.  The
``llm_request.messages`` array gives us the conversation history; the
``llm_response.text`` field gives us the assistant's just-generated reply.
Together that forms the (history, current_query, assistant_response) triple
TurnGate's RL classifier was trained on.

We pipe this triple into ``agent-sec-cli scan-prompt conversation --stdin``
which runs the INTENT_CHAIN detector chain (currently L4 only).  When the
classifier flags the response as harmful we surface an ``ask`` decision so
the user is prompted to abort the run; otherwise we emit ``{}`` (no-op),
since the response has already streamed and there is no benefit to gating
it further.

Fail-open everywhere: every error path returns ``{}`` so a misbehaving
classifier never breaks the user's session.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from trace_context import with_trace_context

# -- config ----------------------------------------------------------------

_CLI_TIMEOUT_SECONDS = 10
_DEFAULT_SOURCE = "cosh_after_model"

# Same checkpoint convention as the sidecar / prompt_scanner module.
_MODEL_DIR = (
    Path.home()
    / ".cache"
    / "prompt_scanner"
    / "models"
    / "TurnGate"
    / "Qwen3-4B"
    / "rl_v4_best"
)

# Permanent marker: once the user has been reminded about the missing
# checkpoint, skip further dialogs until the model is downloaded.
_REMINDER_MARKER_DIR = Path.home() / ".cache" / "agent-sec" / "intent-chain"
_REMINDER_MARKER_FILE = _REMINDER_MARKER_DIR / "warmup-reminded"


# -- helpers ---------------------------------------------------------------


def _noop() -> str:
    """Return an empty cosh HookOutput — no decision."""
    return json.dumps({})


def _is_model_downloaded() -> bool:
    """Heuristic: the dir exists and has a config.json (set by HF save_model)."""
    if not _MODEL_DIR.exists():
        return False
    return (_MODEL_DIR / "config.json").exists()


def _is_warmup_reminded() -> bool:
    return _REMINDER_MARKER_FILE.exists()


def _mark_warmup_reminded() -> None:
    try:
        _REMINDER_MARKER_DIR.mkdir(parents=True, exist_ok=True)
        _REMINDER_MARKER_FILE.write_text("reminded")
    except OSError:
        pass


def _cleanup_warmup_marker() -> None:
    try:
        if _REMINDER_MARKER_FILE.exists():
            _REMINDER_MARKER_FILE.unlink()
    except OSError:
        pass


def _split_triple(messages: list, response_text: str) -> dict | None:
    """Convert AfterModel inputs into a (history, current_query, response) triple.

    Returns ``None`` when there is no user message to anchor the triple on.
    """
    last_user_idx = None
    for i in range(len(messages) - 1, -1, -1):
        m = messages[i]
        if isinstance(m, dict) and m.get("role") == "user":
            last_user_idx = i
            break
    if last_user_idx is None:
        return None

    current_msg = messages[last_user_idx]
    current_query = current_msg.get("content")
    if isinstance(current_query, list):
        # Some agents pass content as a list of parts; flatten any text parts.
        text_parts: list[str] = []
        for part in current_query:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                text_parts.append(part["text"])
            elif isinstance(part, str):
                text_parts.append(part)
        current_query = "\n".join(text_parts)
    if not isinstance(current_query, str) or not current_query.strip():
        return None

    history: list[dict] = []
    for m in messages[:last_user_idx]:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        if role not in ("user", "assistant"):
            continue
        content = m.get("content", "")
        if not isinstance(content, str):
            content = str(content)
        history.append({"role": role, "content": content})

    return {
        "history": history,
        "current_query": current_query,
        "assistant_response": response_text,
    }


def _format_decision(scan_result: dict) -> str:
    """Translate a ScanResult dict into a cosh HookOutput JSON string."""
    verdict = scan_result.get("verdict", "pass")
    if verdict == "pass":
        return _noop()

    summary = scan_result.get("summary") or scan_result.get("threat_type") or (
        "Multi-turn intent classifier flagged the assistant response as harmful."
    )
    msg = f"[multi-turn-intent] {summary}"

    # AfterModel `block` semantics aren't documented; play it safe with `ask`
    # so the user can abort the conversation if they care to.
    if verdict in ("warn", "deny"):
        return json.dumps(
            {"decision": "ask", "reason": msg},
            ensure_ascii=False,
        )
    return _noop()


# -- main ------------------------------------------------------------------


def main() -> None:
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError, ValueError):
        print(_noop())
        return

    if input_data.get("hook_event_name") != "AfterModel":
        print(_noop())
        return

    llm_request = input_data.get("llm_request") or {}
    llm_response = input_data.get("llm_response") or {}
    messages = llm_request.get("messages")
    response_text = llm_response.get("text")
    if not isinstance(messages, list) or not isinstance(response_text, str):
        print(_noop())
        return
    if not response_text.strip():
        print(_noop())
        return

    triple = _split_triple(messages, response_text)
    if triple is None:
        print(_noop())
        return

    # Model not downloaded → one-time reminder, then silently no-op forever
    # (until the checkpoint shows up).
    if not _is_model_downloaded():
        if _is_warmup_reminded():
            print(_noop())
            return
        _mark_warmup_reminded()
        warmup_msg = (
            "[multi-turn-intent] ⚠️  多轮意图识别模型尚未就绪，本次响应未经 L4 检测。\n"
            f"请将训练好的 TurnGate Qwen3-4B 检查点放到：\n"
            f"  {_MODEL_DIR}\n"
            "随后执行：\n"
            "  agent-sec-cli scan-prompt intent-server start\n"
            "此提醒仅出现一次。"
        )
        print(json.dumps({"decision": "ask", "reason": warmup_msg}, ensure_ascii=False))
        return
    _cleanup_warmup_marker()

    payload = {
        "history": triple["history"],
        "current_query": triple["current_query"],
        "assistant_response": triple["assistant_response"],
        "session_id": input_data.get("session_id", ""),
    }

    try:
        cmd = with_trace_context(
            [
                "agent-sec-cli",
                "scan-prompt",
                "conversation",
                "--stdin",
                "--format",
                "json",
                "--source",
                _DEFAULT_SOURCE,
            ],
            input_data,
        )
        proc = subprocess.run(
            cmd,
            input=json.dumps(payload, ensure_ascii=False),
            capture_output=True,
            check=False,
            text=True,
            timeout=_CLI_TIMEOUT_SECONDS,
        )
    except Exception:
        print(_noop())
        return

    if proc.returncode != 0:
        print(_noop())
        return

    try:
        scan_result = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        print(_noop())
        return

    print(_format_decision(scan_result))


if __name__ == "__main__":
    main()
