"""E2E test: CLI capability invocation → event query pipeline.

Validates that invoking security capabilities through the CLI produces
queryable security events in the SQLite store.

NOTE: These tests verify the event-logging pipeline, not the security
capabilities themselves.  `harden` may exit 127 (loongshield missing),
`verify` may find zero skills — both are acceptable as long as an event
is recorded.

Isolation: Each test function uses its own dedicated temp directory (via
AGENT_SEC_DATA_DIR env var) so that tests are fully independent — no
shared state, no ordering dependency, no cascade failures.
"""

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Use the same Python interpreter that runs pytest to invoke the CLI module.
# This works in all environments: local venv, CI (uv run), tox, etc.
_PYTHON = sys.executable
_CLI_MODULE = "agent_sec_cli.cli"


@pytest.fixture(autouse=True)
def _isolated_data_dir(tmp_path):
    """Create a function-scoped temp directory for security event data.

    Each test gets a completely fresh SQLite DB — no cross-test pollution,
    no ordering dependency, no cascade failures.
    """
    data_dir = tmp_path / "agent-sec-e2e"
    data_dir.mkdir()
    os.environ["AGENT_SEC_DATA_DIR"] = str(data_dir)
    yield
    os.environ.pop("AGENT_SEC_DATA_DIR", None)


def _run_cli(*args: str, check: bool = False) -> subprocess.CompletedProcess:
    """Run `python -m agent_sec_cli.cli <args>` and return CompletedProcess."""
    cmd = [_PYTHON, "-m", _CLI_MODULE, *args]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=check,
        timeout=30,
        env=os.environ.copy(),  # inherits AGENT_SEC_DATA_DIR
    )


def _iso_now() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHardenEventLogging:
    """Verify that invoking `harden` produces a queryable event."""

    def test_harden_produces_event(self):
        """After `agent-sec-cli harden`, an event with event_type=harden is queryable."""
        since = _iso_now()

        # Small delay to ensure timestamp ordering
        time.sleep(0.05)

        # Invoke harden — exit code doesn't matter (loongshield may be absent)
        _run_cli("harden")

        # Small delay to let SQLite WAL flush
        time.sleep(0.1)

        # Query events since the start of this test
        result = _run_cli(
            "events", "--event-type", "harden", "--since", since, "--output", "json"
        )
        assert result.returncode == 0, f"events query failed: {result.stderr}"

        events = json.loads(result.stdout)
        assert isinstance(events, list)
        assert (
            len(events) == 1
        ), f"Expected exactly 1 harden event since {since}, got {len(events)}"

        # Verify event structure
        event = events[0]
        assert event["event_type"] == "harden"
        assert event["category"] == "hardening"
        assert "event_id" in event
        assert "timestamp" in event
        assert "details" in event

    def test_harden_event_count(self):
        """--count returns exactly 1 after a single harden invocation."""
        since = _iso_now()
        time.sleep(0.05)

        _run_cli("harden")
        time.sleep(0.1)

        result = _run_cli(
            "events", "--count", "--event-type", "harden", "--since", since
        )
        assert result.returncode == 0
        count = json.loads(result.stdout)
        assert count == 1


class TestVerifyEventLogging:
    """Verify that invoking `verify` produces a queryable event."""

    def test_verify_produces_event(self):
        """After `agent-sec-cli verify`, an event with event_type=verify is queryable."""
        since = _iso_now()
        time.sleep(0.05)

        # Invoke verify — may fail (no skills configured), that's acceptable
        _run_cli("verify")
        time.sleep(0.1)

        # Query events
        result = _run_cli(
            "events", "--event-type", "verify", "--since", since, "--output", "json"
        )
        assert result.returncode == 0

        events = json.loads(result.stdout)
        assert isinstance(events, list)
        assert (
            len(events) == 1
        ), f"Expected exactly 1 verify event since {since}, got {len(events)}"

        event = events[0]
        assert event["event_type"] == "verify"
        assert event["category"] == "asset_verify"
        assert "details" in event

    def test_verify_event_count_by_category(self):
        """--count-by category shows asset_verify: 1 after a single verify invocation."""
        since = _iso_now()
        time.sleep(0.05)

        _run_cli("verify")
        time.sleep(0.1)

        result = _run_cli("events", "--count-by", "category", "--since", since)
        assert result.returncode == 0

        counts = json.loads(result.stdout)
        assert isinstance(counts, dict)
        assert counts == {"asset_verify": 1}


class TestEventQueryFilters:
    """Verify that query filters work end-to-end."""

    def test_last_hours_filter(self):
        """--last-hours returns exactly the single event just created."""
        _run_cli("harden")
        time.sleep(0.1)

        # Fresh DB: only this test's event exists.
        result = _run_cli(
            "events", "--event-type", "harden", "--last-hours", "1", "--output", "json"
        )
        assert result.returncode == 0
        events = json.loads(result.stdout)
        assert len(events) == 1

    def test_nonexistent_type_returns_empty(self):
        """Filtering by a non-existent event_type returns empty list."""
        result = _run_cli(
            "events",
            "--event-type",
            "does_not_exist_xyz",
            "--last-hours",
            "1",
            "--output",
            "json",
        )
        assert result.returncode == 0

        events = json.loads(result.stdout)
        assert events == []

    def test_default_table_output(self):
        """Default output is human-readable table format."""
        since = _iso_now()
        time.sleep(0.05)
        _run_cli("harden")
        time.sleep(0.1)

        result = _run_cli("events", "--event-type", "harden", "--since", since)
        assert result.returncode == 0
        # Default output is table — should NOT be parseable as JSON
        lines = result.stdout.strip().split("\n")
        # Header + 1 data row + blank line + footer
        assert len(lines) == 4
        assert lines[0].startswith("EVENT_TYPE")
        assert "harden" in lines[1]
        assert "succeeded" in lines[1]
        assert "1 event" in lines[3]


class TestCLIValidation:
    """Verify CLI parameter validation and error handling."""

    def test_invalid_output_format(self):
        """Verify that invalid --output format returns error."""
        result = _run_cli("events", "--output", "xml")
        assert result.returncode == 1
        assert "Error:" in result.stderr
        assert "--output must be one of" in result.stderr

    def test_last_hours_and_since_mutual_exclusion(self):
        """Verify that --last-hours and --since are mutually exclusive."""
        result = _run_cli(
            "events",
            "--last-hours",
            "24",
            "--since",
            "2026-01-01T00:00:00Z",
        )
        assert result.returncode == 1
        assert "Error:" in result.stderr
        assert "mutually exclusive" in result.stderr

    def test_count_and_count_by_mutual_exclusion(self):
        """Verify that --count and --count-by are mutually exclusive."""
        result = _run_cli("events", "--count", "--count-by", "category")
        assert result.returncode == 1
        assert "Error:" in result.stderr
        assert "mutually exclusive" in result.stderr

    def test_invalid_count_by_field(self):
        """Verify that invalid --count-by field returns error."""
        result = _run_cli("events", "--count-by", "invalid_field")
        assert result.returncode == 1
        assert "Error:" in result.stderr
        assert "--count-by must be one of" in result.stderr

    def test_unknown_event_type_warning(self):
        """Verify that unknown event_type produces a warning but doesn't fail."""
        result = _run_cli(
            "events",
            "--event-type",
            "unknown_type",
            "--last-hours",
            "1",
            "--output",
            "json",
        )
        # Should succeed (exit 0) but print warning to stderr
        assert result.returncode == 0
        assert "Warning:" in result.stderr
        assert "Unknown event_type" in result.stderr

    def test_unknown_category_warning(self):
        """Verify that unknown category produces a warning but doesn't fail."""
        result = _run_cli(
            "events",
            "--category",
            "unknown_category",
            "--last-hours",
            "1",
            "--output",
            "json",
        )
        # Should succeed (exit 0) but print warning to stderr
        assert result.returncode == 0
        assert "Warning:" in result.stderr
        assert "Unknown category" in result.stderr

    def test_json_output_format(self):
        """Verify that --output json returns a valid JSON array with complete event data."""
        since = _iso_now()
        time.sleep(0.05)
        _run_cli("harden")
        time.sleep(0.1)

        result = _run_cli(
            "events", "--event-type", "harden", "--since", since, "--output", "json"
        )
        assert result.returncode == 0

        # Should be valid JSON array
        events = json.loads(result.stdout)
        assert isinstance(events, list)
        assert len(events) == 1

        # Verify event structure
        event = events[0]
        assert "event_id" in event
        assert "event_type" in event
        assert "category" in event
        assert "result" in event
        assert "timestamp" in event
        assert "details" in event
        assert event["event_type"] == "harden"
        assert event["result"] == "succeeded"

    def test_jsonl_output_format(self):
        """Verify that --output jsonl returns one JSON object per line."""
        since = _iso_now()
        time.sleep(0.05)
        _run_cli("harden")
        time.sleep(0.1)

        result = _run_cli(
            "events", "--event-type", "harden", "--since", since, "--output", "jsonl"
        )
        assert result.returncode == 0

        # Should be newline-delimited JSON
        lines = result.stdout.strip().split("\n")
        assert len(lines) == 1

        # Each line should be valid JSON
        event = json.loads(lines[0])
        assert isinstance(event, dict)
        assert event["event_type"] == "harden"
        assert "event_id" in event
        assert "details" in event

    def test_result_field_in_table_output(self):
        """Verify that result column shows 'succeeded' in table format."""
        since = _iso_now()
        time.sleep(0.05)
        _run_cli("harden")
        time.sleep(0.1)

        result = _run_cli("events", "--event-type", "harden", "--since", since)
        assert result.returncode == 0

        # Table output should contain RESULT column with 'succeeded'
        assert "RESULT" in result.stdout
        assert "succeeded" in result.stdout


# ---------------------------------------------------------------------------
# Tests: --summary flag
# ---------------------------------------------------------------------------


class TestEventsSummaryFlag:
    """Verify the --summary flag on the events command."""

    def test_summary_happy_path(self):
        """--summary produces a human-readable posture report after harden + verify."""
        _run_cli("harden")
        _run_cli("verify")
        time.sleep(0.1)

        result = _run_cli("events", "--summary", "--last-hours", "1")
        assert result.returncode == 0

        out = result.stdout
        # Header
        assert "Security Posture Summary" in out
        assert "System Status:" in out
        # At least one section present
        assert "--- Hardening ---" in out
        # Footer
        assert "Total events:" in out

    def test_summary_incompatible_with_count(self):
        """--summary --count must be rejected with exit code 1."""
        result = _run_cli("events", "--summary", "--count")
        assert result.returncode == 1
        assert "incompatible" in result.stderr.lower()

    def test_summary_incompatible_with_output_json(self):
        """--summary --output json must be rejected with exit code 1."""
        result = _run_cli("events", "--summary", "--output", "json")
        assert result.returncode == 1
        assert "incompatible" in result.stderr.lower()


# ---------------------------------------------------------------------------
# Tests: Error event persistence
# ---------------------------------------------------------------------------


class TestErrorEventPersistence:
    """Verify that error events are correctly persisted to SQLite."""

    def test_error_event_writes_to_sqlite(self):
        """Integration test: verify that error events are actually written to SQLite with result='failed'."""
        from agent_sec_cli.security_events import get_reader, log_event
        from agent_sec_cli.security_events.schema import SecurityEvent

        # Create an error event (simulating what lifecycle.on_error does)
        error_event = SecurityEvent(
            event_type="harden",
            category="hardening",
            result="failed",
            details={
                "request": {"config": "default"},
                "error": "loongshield not found",
                "error_type": "FileNotFoundError",
            },
            trace_id="error-trace-123",
        )

        # Write it via log_event (dual-write)
        log_event(error_event)

        # Read it back from SQLite
        reader = get_reader()
        events = reader.query(event_type="harden")

        assert len(events) == 1
        event = events[0]

        # Verify error event was written correctly
        assert event.event_type == "harden"  # NOT "harden_error"
        assert event.result == "failed"
        assert event.category == "hardening"
        assert event.details["error"] == "loongshield not found"
        assert event.details["error_type"] == "FileNotFoundError"
        assert event.trace_id == "error-trace-123"
