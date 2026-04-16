"""Hook output formatters — convert scan results to hook-specific JSON strings."""

import json

from agent_sec_cli.code_scanner.models import Verdict
from agent_sec_cli.security_middleware.result import ActionResult


def format_allow(mode: str) -> str:
    """Return a permissive (allow / skip=false) JSON string for the given hook mode."""
    if mode == "cosh":
        return json.dumps({"decision": "allow"})
    if mode == "openclaw":
        return json.dumps({"skip": False})
    return ""


def format_cosh(result: ActionResult) -> str:
    """Format ActionResult as cosh HookOutput JSON string."""
    data = result.data or {}
    verdict_str = data.get("verdict", "pass")
    findings = data.get("findings", [])

    if verdict_str == Verdict.PASS.value:
        return json.dumps({"decision": "allow"})

    # WARN and DENY share the same message construction
    descs = [f"- {f['desc_zh']}" for f in findings]
    msg = f"[code-scanner] Detected {len(findings)} issue(s):\n" + "\n".join(descs)

    if verdict_str == Verdict.WARN.value:
        return json.dumps(
            {"decision": "allow", "systemMessage": msg}, ensure_ascii=False
        )
    if verdict_str == Verdict.DENY.value:
        return json.dumps({"decision": "block", "reason": msg}, ensure_ascii=False)
    return json.dumps({"decision": "allow"})


def format_openclaw(result: ActionResult) -> str:
    """Format ActionResult as OpenClaw hook JSON string."""
    data = result.data or {}
    verdict_str = data.get("verdict", "pass")
    summary = data.get("summary", "")

    if verdict_str in (Verdict.PASS.value, Verdict.ERROR.value):
        return json.dumps({"skip": False})
    if verdict_str == Verdict.WARN.value:
        return json.dumps(
            {"skip": False, "skipReason": f"[code-scanner] {summary}"},
            ensure_ascii=False,
        )
    if verdict_str == Verdict.DENY.value:
        return json.dumps(
            {"skip": True, "skipReason": f"[code-scanner] {summary}"},
            ensure_ascii=False,
        )
    return json.dumps({"skip": False})
