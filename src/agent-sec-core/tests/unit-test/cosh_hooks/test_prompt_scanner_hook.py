"""Unit tests for cosh-extension/hooks/prompt_scanner_hook.py.

The hook is self-contained (no agent_sec_cli imports), so we test it
by importing the _format_cosh helper directly and piping JSON via
subprocess for integration-style tests.

Tests cover:
1. verdict → decision mapping (pass, warn, deny, error, unknown)
2. Warmup detection via string matching in summary
3. Non-warmup error verdict still fails open
4. Subprocess integration: pipe JSON into the hook and verify stdout
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

# Path to the standalone cosh hook script
_COSH_HOOK = str(
    Path(__file__).resolve().parents[2]
    / ".."
    / "cosh-extension"
    / "hooks"
    / "prompt_scanner_hook.py"
)

# Import _format_cosh for direct unit testing
sys.path.insert(0, str(Path(_COSH_HOOK).parent))
from prompt_scanner_hook import _WARMUP_HINT, _format_cosh

# ---------------------------------------------------------------------------
# Unit tests: _format_cosh
# ---------------------------------------------------------------------------


class TestFormatCoshPass:
    """verdict=pass → decision=allow."""

    def test_pass_returns_allow(self):
        result = json.loads(_format_cosh({"verdict": "pass"}))
        assert result["decision"] == "allow"

    def test_pass_ignores_summary(self):
        result = json.loads(_format_cosh({"verdict": "pass", "summary": "anything"}))
        assert result["decision"] == "allow"


class TestFormatCoshWarn:
    """verdict=warn → decision=ask with reason."""

    def test_warn_returns_ask(self):
        result = json.loads(
            _format_cosh({"verdict": "warn", "summary": "suspicious prompt"})
        )
        assert result["decision"] == "ask"
        assert "suspicious prompt" in result["reason"]
        assert "[prompt-scanner]" in result["reason"]

    def test_warn_uses_threat_type_when_no_summary(self):
        result = json.loads(
            _format_cosh({"verdict": "warn", "threat_type": "direct_injection"})
        )
        assert result["decision"] == "ask"
        assert "direct_injection" in result["reason"]

    def test_warn_uses_default_when_no_summary_no_threat_type(self):
        result = json.loads(_format_cosh({"verdict": "warn"}))
        assert result["decision"] == "ask"
        assert "Prompt rejected by security policy" in result["reason"]


class TestFormatCoshDeny:
    """verdict=deny → decision=ask with reason."""

    def test_deny_returns_ask(self):
        result = json.loads(
            _format_cosh({"verdict": "deny", "summary": "jailbreak detected"})
        )
        assert result["decision"] == "ask"
        assert "jailbreak detected" in result["reason"]


class TestFormatCoshErrorWarmup:
    """verdict=error + summary contains warmup hint → decision=ask with warmup message."""

    def test_error_with_warmup_hint_in_summary_returns_ask(self):
        result = json.loads(
            _format_cosh(
                {
                    "verdict": "error",
                    "summary": f"Scanner error: Model not found. Run {_WARMUP_HINT}",
                }
            )
        )
        assert result["decision"] == "ask"
        assert "warmup" in result["reason"]
        assert "agent-sec-cli scan-prompt warmup" in result["reason"]

    def test_warmup_message_contains_chinese_instructions(self):
        result = json.loads(
            _format_cosh(
                {
                    "verdict": "error",
                    "summary": f"Model not available. {_WARMUP_HINT}",
                }
            )
        )
        assert result["decision"] == "ask"
        assert "agent-sec-cli scan-prompt warmup" in result["reason"]


class TestFormatCoshErrorOther:
    """verdict=error without warmup hint → fail-open allow."""

    def test_error_without_warmup_hint_returns_allow(self):
        result = json.loads(
            _format_cosh(
                {
                    "verdict": "error",
                    "summary": "internal scanner failure",
                }
            )
        )
        assert result["decision"] == "allow"

    def test_error_with_empty_summary_returns_allow(self):
        result = json.loads(_format_cosh({"verdict": "error"}))
        assert result["decision"] == "allow"


class TestFormatCoshUnknown:
    """Unknown verdict → fail-open allow."""

    def test_unknown_verdict_returns_allow(self):
        result = json.loads(_format_cosh({"verdict": "unknown"}))
        assert result["decision"] == "allow"

    def test_missing_verdict_defaults_to_allow(self):
        """When verdict key is missing, default is 'pass' → allow."""
        result = json.loads(_format_cosh({}))
        assert result["decision"] == "allow"


# ---------------------------------------------------------------------------
# Integration tests: subprocess (pipe JSON into hook, verify stdout)
# ---------------------------------------------------------------------------


class TestCoshHookSubprocess:
    """Integration tests: pipe JSON into prompt_scanner_hook.py and verify stdout."""

    def _run_hook(self, input_data: dict) -> dict:
        proc = subprocess.run(
            [sys.executable, _COSH_HOOK],
            input=json.dumps(input_data),
            capture_output=True,
            text=True,
            timeout=15,
        )
        # Hook always exits 0
        assert proc.returncode == 0, f"Hook stderr: {proc.stderr}"
        return json.loads(proc.stdout)

    def test_empty_prompt_allows(self):
        output = self._run_hook({"prompt": ""})
        assert output["decision"] == "allow"

    def test_invalid_json_allows(self):
        """Malformed stdin should fail-open with allow."""
        proc = subprocess.run(
            [sys.executable, _COSH_HOOK],
            input="not-json",
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert proc.returncode == 0
        output = json.loads(proc.stdout)
        assert output["decision"] == "allow"

    def test_missing_prompt_key_allows(self):
        output = self._run_hook({"session_id": "abc"})
        assert output["decision"] == "allow"
