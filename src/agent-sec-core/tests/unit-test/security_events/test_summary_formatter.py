"""Unit tests for security_events.summary_formatter."""

from datetime import datetime, timedelta, timezone
from typing import Any

from agent_sec_cli.security_events.schema import SecurityEvent
from agent_sec_cli.security_events.summary_formatter import format_summary

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    event_type: str = "test",
    category: str = "test",
    result: str = "succeeded",
    details: dict[str, Any] | None = None,
    timestamp: str | None = None,
) -> SecurityEvent:
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    return SecurityEvent(
        event_type=event_type,
        category=category,
        result=result,
        details=details or {},
        timestamp=timestamp,
    )


def _ts_minutes_ago(minutes: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return dt.isoformat()


# ---------------------------------------------------------------------------
# Test: empty events
# ---------------------------------------------------------------------------


class TestEmptyEvents:
    def test_empty_list_returns_guidance_message(self):
        output = format_summary([], "last 24 hours")
        assert "No security events recorded" in output


# ---------------------------------------------------------------------------
# Test: hardening summary
# ---------------------------------------------------------------------------


class TestHardeningSummary:
    def test_scan_count_and_compliance(self):
        events = [
            _make_event(
                event_type="harden",
                category="hardening",
                result="succeeded",
                details={
                    "request": {"args": ["--scan", "--config", "agentos_baseline"]},
                    "result": {
                        "mode": "scan",
                        "config": "agentos_baseline",
                        "passed": 45,
                        "failed": 3,
                        "total": 48,
                        "failures": [
                            {
                                "rule_id": "SEC-001",
                                "status": "FAIL",
                                "message": "SSH root login not disabled",
                            },
                            {
                                "rule_id": "SEC-003",
                                "status": "FAIL",
                                "message": "Firewall rules not updated",
                            },
                            {
                                "rule_id": "SEC-005",
                                "status": "FAIL",
                                "message": "Audit log disabled",
                            },
                        ],
                        "fixed": 0,
                        "manual": 0,
                        "dry_run_pending": 0,
                        "fixed_items": [],
                    },
                },
                timestamp=_ts_minutes_ago(10),
            ),
            _make_event(
                event_type="harden",
                category="hardening",
                result="succeeded",
                details={
                    "request": {"args": ["--scan", "--config", "agentos_baseline"]},
                    "result": {
                        "mode": "scan",
                        "config": "agentos_baseline",
                        "passed": 48,
                        "failed": 0,
                        "total": 48,
                        "failures": [],
                        "fixed": 0,
                        "manual": 0,
                        "dry_run_pending": 0,
                        "fixed_items": [],
                    },
                },
                timestamp=_ts_minutes_ago(60),
            ),
        ]
        output = format_summary(events, "last 24 hours")

        assert "--- Hardening ---" in output
        assert "Scans performed:  2 (succeeded: 2, failed: 0)" in output
        assert "45/48 rules passed (93.8%)" in output
        assert "agent-sec-cli harden --scan" in output

    def test_reinforcement_count(self):
        events = [
            _make_event(
                event_type="harden",
                category="hardening",
                result="succeeded",
                details={
                    "request": {
                        "args": ["--reinforce", "--config", "agentos_baseline"]
                    },
                    "result": {
                        "mode": "reinforce",
                        "config": "agentos_baseline",
                        "passed": 48,
                        "failed": 0,
                        "total": 48,
                        "failures": [],
                        "fixed": 2,
                        "manual": 0,
                        "dry_run_pending": 0,
                        "fixed_items": [],
                    },
                },
                timestamp=_ts_minutes_ago(5),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "Reinforcements:   1 (succeeded: 1, failed: 0)" in output

    def test_failed_scan(self):
        events = [
            _make_event(
                event_type="harden",
                category="hardening",
                result="failed",
                details={
                    "request": {"args": ["--scan", "--config", "agentos_baseline"]},
                    "error": "loongshield not found",
                    "error_type": "FileNotFoundError",
                },
                timestamp=_ts_minutes_ago(5),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "Scans performed:  1 (succeeded: 0, failed: 1)" in output
        assert "Latest scan failed: loongshield not found" in output
        # Latest harden failed -> needs_attention (not critical)
        assert "Needs attention" in output


# ---------------------------------------------------------------------------
# Test: asset verify summary
# ---------------------------------------------------------------------------


class TestAssetVerifySummary:
    def test_successful_verifications(self):
        events = [
            _make_event(
                event_type="verify",
                category="asset_verify",
                result="succeeded",
                details={
                    "request": {"skill": None},
                    "result": {"passed": 5, "failed": 0},
                },
                timestamp=_ts_minutes_ago(14),
            ),
            _make_event(
                event_type="verify",
                category="asset_verify",
                result="succeeded",
                details={
                    "request": {"skill": "/opt/skills/my-skill"},
                    "result": {"passed": 3, "failed": 1},
                },
                timestamp=_ts_minutes_ago(120),
            ),
        ]
        output = format_summary(events, "last 24 hours")

        assert "--- Asset Verification ---" in output
        assert "Verifications performed: 2 (succeeded: 2, failed: 0)" in output
        assert "5 passed, 0 failed" in output
        assert "ALL CLEAR" in output

    def test_failed_verification(self):
        events = [
            _make_event(
                event_type="verify",
                category="asset_verify",
                result="succeeded",
                details={
                    "request": {"skill": None},
                    "result": {"passed": 3, "failed": 2},
                },
                timestamp=_ts_minutes_ago(5),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "FAILURES DETECTED" in output
        assert "3 passed, 2 failed" in output


# ---------------------------------------------------------------------------
# Test: code scan summary
# ---------------------------------------------------------------------------


class TestCodeScanSummary:
    def test_deny_findings(self):
        events = [
            _make_event(
                event_type="code_scan",
                category="code_scan",
                result="succeeded",
                details={
                    "request": {"code": "rm -rf /", "language": "bash"},
                    "result": {
                        "ok": False,
                        "verdict": "deny",
                        "summary": "Dangerous code detected",
                        "findings": [
                            {
                                "rule_id": "BASH-001",
                                "severity": "deny",
                                "desc_en": "Remote code execution",
                                "desc_zh": "远程代码执行",
                                "evidence": ["rm -rf /"],
                            },
                        ],
                        "language": "bash",
                        "engine_version": "0.1.0",
                        "elapsed_ms": 5,
                    },
                },
                timestamp=_ts_minutes_ago(3),
            ),
        ]
        output = format_summary(events, "last 24 hours")

        assert "--- Code Scanning ---" in output
        assert "Scans performed: 1 (succeeded: 1, failed: 0)" in output
        assert "deny: 1" in output

    def test_pass_verdict_no_deny_section(self):
        events = [
            _make_event(
                event_type="code_scan",
                category="code_scan",
                result="succeeded",
                details={
                    "request": {"code": "echo hello", "language": "bash"},
                    "result": {
                        "ok": True,
                        "verdict": "pass",
                        "summary": "No issues",
                        "findings": [],
                        "language": "bash",
                        "engine_version": "0.1.0",
                        "elapsed_ms": 2,
                    },
                },
                timestamp=_ts_minutes_ago(10),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "pass: 1" in output
        assert "Recent deny findings" not in output

    def test_mixed_verdicts_breakdown(self):
        events = [
            _make_event(
                event_type="code_scan",
                category="code_scan",
                result="succeeded",
                details={
                    "request": {"code": "x", "language": "bash"},
                    "result": {"ok": True, "verdict": "pass", "findings": []},
                },
                timestamp=_ts_minutes_ago(1),
            ),
            _make_event(
                event_type="code_scan",
                category="code_scan",
                result="succeeded",
                details={
                    "request": {"code": "y", "language": "bash"},
                    "result": {
                        "ok": True,
                        "verdict": "warn",
                        "findings": [
                            {
                                "rule_id": "W1",
                                "severity": "warn",
                                "desc_en": "w",
                                "desc_zh": "w",
                                "evidence": [],
                            }
                        ],
                    },
                },
                timestamp=_ts_minutes_ago(2),
            ),
            _make_event(
                event_type="code_scan",
                category="code_scan",
                result="succeeded",
                details={
                    "request": {"code": "z", "language": "bash"},
                    "result": {"ok": True, "verdict": "pass", "findings": []},
                },
                timestamp=_ts_minutes_ago(3),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "pass: 2, warn: 1" in output


# ---------------------------------------------------------------------------
# Test: sandbox summary
# ---------------------------------------------------------------------------


class TestSandboxSummary:
    def test_sandbox_interventions(self):
        events = [
            _make_event(
                event_type="sandbox_prehook",
                category="sandbox",
                result="succeeded",
                details={
                    "request": {
                        "decision": "sandbox",
                        "command": "rm -rf /tmp/data",
                        "reasons": "recursive delete",
                        "network_policy": "none",
                        "cwd": "/home/user",
                    },
                    "result": {
                        "decision": "sandbox",
                        "command": "rm -rf /tmp/data",
                        "reasons": "recursive delete",
                        "network_policy": "none",
                        "cwd": "/home/user",
                    },
                },
                timestamp=_ts_minutes_ago(2),
            ),
            _make_event(
                event_type="sandbox_prehook",
                category="sandbox",
                result="succeeded",
                details={
                    "request": {
                        "decision": "block",
                        "command": "chmod 777 /etc/shadow",
                        "reasons": "permission escalation",
                        "network_policy": "none",
                        "cwd": "/home/user",
                    },
                    "result": {
                        "decision": "block",
                        "command": "chmod 777 /etc/shadow",
                        "reasons": "permission escalation",
                        "network_policy": "none",
                        "cwd": "/home/user",
                    },
                },
                timestamp=_ts_minutes_ago(5),
            ),
        ]
        output = format_summary(events, "last 24 hours")

        assert "--- Sandbox Guard ---" in output
        assert "Total interventions: 2" in output
        # Sandbox no longer exposes raw commands for security reasons
        assert "rm -rf /tmp/data" not in output
        assert "chmod 777" not in output


# ---------------------------------------------------------------------------
# Test: posture computation
# ---------------------------------------------------------------------------


class TestPostureComputation:
    def test_good_status(self):
        events = [
            _make_event(
                event_type="verify",
                category="asset_verify",
                result="succeeded",
                details={"request": {}, "result": {"passed": 5, "failed": 0}},
                timestamp=_ts_minutes_ago(10),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "Good" in output
        assert "\u2713" in output

    def test_sandbox_block_does_not_affect_posture(self):
        """Sandbox events are independent — they must NOT affect posture status."""
        events = [
            _make_event(
                event_type="harden",
                category="hardening",
                result="succeeded",
                details={
                    "request": {"args": ["--scan"]},
                    "result": {
                        "mode": "scan",
                        "passed": 48,
                        "failed": 0,
                        "total": 48,
                        "failures": [],
                    },
                },
                timestamp=_ts_minutes_ago(5),
            ),
            _make_event(
                event_type="sandbox_prehook",
                category="sandbox",
                result="succeeded",
                details={
                    "request": {
                        "decision": "block",
                        "command": "rm /etc/passwd",
                        "reasons": "critical file",
                        "network_policy": "none",
                        "cwd": "/",
                    },
                    "result": {
                        "decision": "block",
                        "command": "rm /etc/passwd",
                        "reasons": "critical file",
                        "network_policy": "none",
                        "cwd": "/",
                    },
                },
                timestamp=_ts_minutes_ago(10),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "Good" in output
        assert "\u2713" in output

    def test_critical_on_harden_failure(self):
        """Latest harden failed -> needs_attention (tool error, not security violation)."""
        events = [
            _make_event(
                event_type="harden",
                category="hardening",
                result="failed",
                details={
                    "request": {"args": ["--scan"]},
                    "error": "tool not found",
                    "error_type": "FileNotFoundError",
                },
                timestamp=_ts_minutes_ago(5),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "Needs attention" in output
        assert "\u26a0" in output

    def test_code_deny_does_not_affect_posture(self):
        """Code scan is an independent category — deny must NOT affect posture."""
        events = [
            _make_event(
                event_type="code_scan",
                category="code_scan",
                result="succeeded",
                details={
                    "request": {"code": "bad", "language": "bash"},
                    "result": {
                        "ok": False,
                        "verdict": "deny",
                        "summary": "Deny",
                        "findings": [
                            {
                                "rule_id": "X",
                                "severity": "deny",
                                "desc_en": "bad",
                                "desc_zh": "bad",
                                "evidence": [],
                            }
                        ],
                        "language": "bash",
                        "engine_version": "0.1.0",
                        "elapsed_ms": 1,
                    },
                },
                timestamp=_ts_minutes_ago(1),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "Good" in output
        assert "\u2713" in output


# ---------------------------------------------------------------------------
# Test: defensive sort (events given in wrong order)
# ---------------------------------------------------------------------------


class TestDefensiveSort:
    def test_asc_order_events_still_pick_latest(self):
        """Events passed in ascending order must still produce correct 'latest' results."""
        older = _make_event(
            event_type="harden",
            category="hardening",
            result="succeeded",
            details={
                "request": {"args": ["--scan"]},
                "result": {
                    "mode": "scan",
                    "passed": 48,
                    "failed": 0,
                    "total": 48,
                    "failures": [],
                },
            },
            timestamp=_ts_minutes_ago(60),
        )
        newer = _make_event(
            event_type="harden",
            category="hardening",
            result="succeeded",
            details={
                "request": {"args": ["--scan"]},
                "result": {
                    "mode": "scan",
                    "passed": 40,
                    "failed": 8,
                    "total": 48,
                    "failures": [{"rule_id": "SEC-001"}],
                },
            },
            timestamp=_ts_minutes_ago(5),
        )
        # Pass in ASCENDING order — older first
        output = format_summary([older, newer], "last 24 hours")
        # Latest (newer) has 40/48 compliance — not the older 48/48
        assert "40/48 rules passed" in output
        assert "Needs attention" in output


# ---------------------------------------------------------------------------
# Test: posture – verify failed path
# ---------------------------------------------------------------------------


class TestPostureVerifyFailed:
    def test_verify_event_failed_triggers_needs_attention(self):
        """Latest verify event.result=='failed' triggers needs_attention."""
        events = [
            _make_event(
                event_type="verify",
                category="asset_verify",
                result="failed",
                details={
                    "request": {"skill": None},
                    "error": "timeout",
                    "error_type": "TimeoutError",
                },
                timestamp=_ts_minutes_ago(5),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "Needs attention" in output
        assert "\u26a0" in output


# ---------------------------------------------------------------------------
# Test: suggestions edge cases
# ---------------------------------------------------------------------------


class TestSuggestionsEdgeCases:
    def test_no_suggestion_when_latest_harden_failed(self):
        """If latest harden event.result=='failed', do NOT suggest --reinforce."""
        events = [
            _make_event(
                event_type="harden",
                category="hardening",
                result="failed",
                details={"request": {"args": ["--scan"]}, "error": "not found"},
                timestamp=_ts_minutes_ago(5),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "agent-sec-cli harden --reinforce" not in output

    def test_no_suggestion_when_no_hardening_events(self):
        """Only sandbox events — no suggestion at all."""
        events = [
            _make_event(
                event_type="sandbox_prehook",
                category="sandbox",
                result="succeeded",
                details={
                    "request": {"decision": "block", "command": "x"},
                    "result": {"decision": "block"},
                },
                timestamp=_ts_minutes_ago(5),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "Suggested actions" not in output


# ---------------------------------------------------------------------------
# Test: output format exact prefixes
# ---------------------------------------------------------------------------


class TestOutputFormatPrefixes:
    def test_system_status_good_prefix(self):
        events = [
            _make_event(
                event_type="verify",
                category="asset_verify",
                result="succeeded",
                details={"request": {}, "result": {"passed": 5, "failed": 0}},
                timestamp=_ts_minutes_ago(10),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "System Status: Good" in output

    def test_system_status_needs_attention_prefix(self):
        events = [
            _make_event(
                event_type="harden",
                category="hardening",
                result="failed",
                details={"request": {"args": ["--scan"]}, "error": "err"},
                timestamp=_ts_minutes_ago(5),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "System Status: Needs attention" in output

    def test_verdict_prefix_in_code_scan(self):
        events = [
            _make_event(
                event_type="code_scan",
                category="code_scan",
                result="succeeded",
                details={
                    "request": {"code": "ls", "language": "bash"},
                    "result": {"ok": True, "verdict": "pass", "findings": []},
                },
                timestamp=_ts_minutes_ago(5),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "Verdict: pass: 1" in output


# ---------------------------------------------------------------------------
# Test: mixed categories
# ---------------------------------------------------------------------------


class TestMixedCategories:
    def test_combined_report_structure(self):
        events = [
            _make_event(
                event_type="harden",
                category="hardening",
                result="succeeded",
                details={
                    "request": {"args": ["--scan", "--config", "agentos_baseline"]},
                    "result": {
                        "mode": "scan",
                        "config": "agentos_baseline",
                        "passed": 46,
                        "failed": 2,
                        "total": 48,
                        "failures": [
                            {"rule_id": "SEC-001", "status": "FAIL", "message": "Issue"}
                        ],
                        "fixed": 0,
                        "manual": 0,
                        "dry_run_pending": 0,
                        "fixed_items": [],
                    },
                },
                timestamp=_ts_minutes_ago(5),
            ),
            _make_event(
                event_type="verify",
                category="asset_verify",
                result="succeeded",
                details={
                    "request": {"skill": None},
                    "result": {"passed": 5, "failed": 0},
                },
                timestamp=_ts_minutes_ago(10),
            ),
            _make_event(
                event_type="code_scan",
                category="code_scan",
                result="succeeded",
                details={
                    "request": {"code": "echo hi", "language": "bash"},
                    "result": {
                        "ok": True,
                        "verdict": "pass",
                        "summary": "OK",
                        "findings": [],
                        "language": "bash",
                        "engine_version": "0.1.0",
                        "elapsed_ms": 1,
                    },
                },
                timestamp=_ts_minutes_ago(15),
            ),
        ]
        output = format_summary(events, "last 24 hours")

        # Verify all sections present
        assert "Security Posture Summary (last 24 hours)" in output
        assert "--- Hardening ---" in output
        assert "--- Asset Verification ---" in output
        assert "--- Code Scanning ---" in output
        assert "Total events: 3" in output

        # Verify sections appear in correct order
        hardening_pos = output.index("--- Hardening ---")
        verify_pos = output.index("--- Asset Verification ---")
        code_pos = output.index("--- Code Scanning ---")
        assert hardening_pos < verify_pos < code_pos


# ---------------------------------------------------------------------------
# Test: footer and suggestions
# ---------------------------------------------------------------------------


class TestFooter:
    def test_footer_stats(self):
        """Latest harden succeeded so posture not critical; footer shows stats."""
        events = [
            _make_event(
                event_type="harden",
                category="hardening",
                result="succeeded",
                details={
                    "request": {"args": ["--scan"]},
                    "result": {
                        "mode": "scan",
                        "passed": 48,
                        "failed": 0,
                        "total": 48,
                        "failures": [],
                    },
                },
                timestamp=_ts_minutes_ago(14),
            ),
            _make_event(
                event_type="harden",
                category="hardening",
                result="failed",
                details={
                    "request": {"args": ["--scan"]},
                    "error": "timeout",
                    "error_type": "TimeoutError",
                },
                timestamp=_ts_minutes_ago(30),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "Total events: 2" in output
        assert "Failed: 1" in output
        # Latest event succeeded, so posture should be Good, not Critical
        assert "Good" in output

    def test_suggested_action_for_failed_rules(self):
        events = [
            _make_event(
                event_type="harden",
                category="hardening",
                result="succeeded",
                details={
                    "request": {"args": ["--scan"]},
                    "result": {
                        "mode": "scan",
                        "passed": 45,
                        "failed": 3,
                        "total": 48,
                        "failures": [
                            {"rule_id": "SEC-001", "status": "FAIL", "message": "issue"}
                        ],
                    },
                },
                timestamp=_ts_minutes_ago(5),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "agent-sec-cli harden --reinforce" in output
        # Latest harden has failures -> needs_attention
        assert "Needs attention" in output

    def test_needs_attention_on_latest_harden_failures(self):
        """Latest successful scan with non-empty failures triggers needs_attention."""
        events = [
            _make_event(
                event_type="harden",
                category="hardening",
                result="succeeded",
                details={
                    "request": {"args": ["--scan"]},
                    "result": {
                        "mode": "scan",
                        "passed": 45,
                        "failed": 3,
                        "total": 48,
                        "failures": [{"rule_id": "SEC-001"}],
                    },
                },
                timestamp=_ts_minutes_ago(5),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "Needs attention" in output
        assert "\u26a0" in output

    def test_needs_attention_on_latest_verify_failures(self):
        """Latest verify with failed > 0 triggers needs_attention."""
        events = [
            _make_event(
                event_type="verify",
                category="asset_verify",
                result="succeeded",
                details={"request": {}, "result": {"passed": 3, "failed": 1}},
                timestamp=_ts_minutes_ago(5),
            ),
        ]
        output = format_summary(events, "last 24 hours")
        assert "Needs attention" in output
        assert "\u26a0" in output
