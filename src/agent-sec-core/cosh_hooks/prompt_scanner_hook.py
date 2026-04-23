#!/usr/bin/env python3
"""Cosh hook script for prompt-scanner.

Reads a cosh UserPromptSubmit JSON from stdin, extracts the user prompt,
invokes ``agent-sec-cli scan-prompt`` via subprocess, and writes a cosh
HookOutput JSON to stdout.

Usage::

    python3 prompt_scanner_hook.py          # reads stdin, writes stdout

Hook point: **UserPromptSubmit** — fires when the user submits a prompt.
Input schema::

    {
        "session_id": "...",
        "hook_event_name": "UserPromptSubmit",
        "prompt": "<user prompt text>"
    }

This script is intentionally self-contained — it does NOT import any
``agent_sec_cli`` package.  All it needs is the standard library and the
``agent-sec-cli`` on $PATH.
"""

import json
import subprocess
import sys

# -- config ----------------------------------------------------------------

_DEFAULT_MODE = "standard"
_DEFAULT_SOURCE = "user_input"


# -- helpers ---------------------------------------------------------------


def _allow() -> str:
    """Return a permissive cosh HookOutput JSON string."""
    return json.dumps({"decision": "allow"})


def _format_cosh(scan_result: dict) -> str:
    """Convert a ScanResult dict into a cosh HookOutput JSON string.

    Mapping:
        verdict == "pass"  -> decision "allow"
        verdict == "warn"  -> decision "ask"  (let user decide)
        verdict == "deny"  -> decision "block" (reject the prompt)
        otherwise          -> fail-open "allow"
    """
    verdict = scan_result.get("verdict", "pass")
    findings = scan_result.get("findings", [])

    if verdict == "pass":
        return json.dumps({"decision": "allow"})

    # Build a concise one-line reason from the highest-severity finding.
    # Prefer summary field; fall back to first finding title + evidence.
    summary = scan_result.get("summary", "")
    threat_type = scan_result.get("threat_type", "")
    confidence = scan_result.get("confidence", 0.0)

    if findings:
        f = findings[0]
        title = f.get("title") or f.get("desc_zh") or f.get("desc_en") or f.get("rule_id", "issue detected")
        evidence = f.get("evidence", "")
        pct = f"{confidence * 100:.1f}%"
        if evidence:
            msg = f'[prompt-scanner] {title} — "{evidence}"'
        else:
            msg = f"[prompt-scanner] {title}"
    else:
        msg = f"[prompt-scanner] {summary or threat_type or 'Prompt rejected by security policy'}"

    if verdict == "warn":
        return json.dumps(
            {"decision": "ask", "reason": msg},
            ensure_ascii=False,
        )
    # v1 soft-launch: deny also maps to "ask" to avoid blocking users outright.
    # TODO: switch to "block" once the policy is mature enough.
    if verdict == "deny":
        return json.dumps(
            {"decision": "deny", "reason": msg},
            ensure_ascii=False,
        )
    # error or unknown -> fail-open
    return json.dumps({"decision": "allow"})


# -- main ------------------------------------------------------------------


def main() -> None:
    print("[prompt-scanner] hook entered", file=sys.stderr)

    # 1. Read stdin JSON (UserPromptSubmit event)
    try:
        input_data = json.load(sys.stdin)
    except (json.JSONDecodeError, EOFError, ValueError) as e:
        print(f"[prompt-scanner] failed to parse stdin JSON: {e}", file=sys.stderr)
        print(_allow())
        return

    # 2. Extract user prompt text
    print(f"[prompt-scanner] stdin keys: {list(input_data.keys())}", file=sys.stderr)
    print(f"[prompt-scanner] full stdin: {json.dumps(input_data, ensure_ascii=False)}", file=sys.stderr)
    prompt_text = input_data.get("prompt", "")
    print(f"[prompt-scanner] scanning: {prompt_text!r}", file=sys.stderr)
    if not prompt_text or not isinstance(prompt_text, str) or not prompt_text.strip():
        print("[prompt-scanner] empty or invalid prompt, allowing", file=sys.stderr)
        print(_allow())
        return

    # 3. Call agent-sec-cli scan-prompt via subprocess
    print(f"[prompt-scanner] invoking agent-sec-cli (mode={_DEFAULT_MODE})", file=sys.stderr)
    try:
        proc = subprocess.run(
            [
                "agent-sec-cli",
                "scan-prompt",
                "--text",
                prompt_text,
                "--mode",
                _DEFAULT_MODE,
                "--format",
                "json",
                "--source",
                _DEFAULT_SOURCE,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception as e:
        # Timeout or other error -> fail-open
        print(f"[prompt-scanner] subprocess error: {e}", file=sys.stderr)
        print(_allow())
        return

    print(f"[prompt-scanner] agent-sec-cli returncode={proc.returncode}", file=sys.stderr)
    if proc.returncode != 0:
        print(f"[prompt-scanner] agent-sec-cli stderr: {proc.stderr!r}", file=sys.stderr)
        print(_allow())
        return

    # 4. Parse ScanResult JSON from stdout
    # agent-sec-cli may print non-JSON lines (e.g. model download progress) before
    # the actual JSON output.  Find the first '{' and parse from there.
    try:
        json_start = proc.stdout.index('{')
        scan_result = json.loads(proc.stdout[json_start:])
    except (ValueError, json.JSONDecodeError) as e:
        print(f"[prompt-scanner] failed to parse scan result: {e}, stdout={proc.stdout!r}", file=sys.stderr)
        print(_allow())
        return

    verdict = scan_result.get('verdict', 'unknown')
    print(f"[prompt-scanner] verdict={verdict}", file=sys.stderr)

    # 5. Format and print cosh output
    result = _format_cosh(scan_result)
    print(f"[prompt-scanner] cosh output: {result}", file=sys.stderr)
    print(result)


if __name__ == "__main__":
    main()
