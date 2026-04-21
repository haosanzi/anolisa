"""Human-readable security posture summary from SecurityEvent records.

Aggregates events by category and produces an actionable text report
suitable for CLI stdout or upstream consumer display.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from agent_sec_cli.security_events.schema import SecurityEvent

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def format_summary(events: list[SecurityEvent], time_label: str) -> str:
    """Produce a human-readable summary from a list of security events.

    Parameters
    ----------
    events : list[SecurityEvent]
        Pre-queried events (ordering not required; sorted internally).
    time_label : str
        Human label for the time window (e.g., "last 24 hours").

    Returns
    -------
    str
        Formatted multi-section summary text.
    """
    if not events:
        return "No security events recorded.\n"

    by_category = _group_by_category(events)
    sections: list[str] = []

    harden_events = by_category.get("hardening", [])
    asset_events = by_category.get("asset_verify", [])
    code_scan_events = by_category.get("code_scan", [])
    sandbox_events = by_category.get("sandbox", [])

    if harden_events:
        sections.append(_summarize_hardening(harden_events))
    if asset_events:
        sections.append(_summarize_asset_verify(asset_events))
    if code_scan_events:
        sections.append(_summarize_code_scan(code_scan_events))
    if sandbox_events:
        sections.append(_summarize_sandbox(sandbox_events))

    header = _compute_posture(harden_events, asset_events, time_label)
    footer = _build_footer(events, harden_events)
    return "\n\n".join([header, *sections, footer])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _group_by_category(events: list[SecurityEvent]) -> dict[str, list[SecurityEvent]]:
    """Group events into a dict keyed by category, newest-first."""
    by_category: dict[str, list[SecurityEvent]] = defaultdict(list)
    for e in events:
        by_category[e.category].append(e)
    # Ensure each group is sorted newest-first regardless of input order.
    for cat in by_category:
        by_category[cat].sort(key=lambda e: e.timestamp, reverse=True)
    return by_category


def _safe_details(event: SecurityEvent) -> dict[str, Any]:
    """Return event.details safely, defaulting to empty dict."""
    return event.details if isinstance(event.details, dict) else {}


def _get_result(event: SecurityEvent) -> dict[str, Any]:
    """Extract details.result dict from an event."""
    d = _safe_details(event)
    result = d.get("result")
    return result if isinstance(result, dict) else {}


def _get_request(event: SecurityEvent) -> dict[str, Any]:
    """Extract details.request dict from an event."""
    d = _safe_details(event)
    request = d.get("request")
    return request if isinstance(request, dict) else {}


def _get_mode(event: SecurityEvent) -> str:
    """Extract hardening mode from details.result, fallback to parsing request.args.

    The mode field is written by HardeningBackend._build_result_data into
    ActionResult.data, which lifecycle.post_action stores as details.result.
    The CLI passes raw args (e.g. ["--scan", "--config", ...]) as
    details.request.args, so we parse those as a fallback.
    """
    result = _get_result(event)
    mode = result.get("mode")
    if mode:
        return mode
    # Fallback: parse request.args for --scan/--reinforce/--dry-run
    args = _get_request(event).get("args", [])
    if isinstance(args, (list, tuple)):
        if "--dry-run" in args:
            return "dry-run"
        if "--reinforce" in args:
            return "reinforce"
        if "--scan" in args:
            return "scan"
    return ""


# ---------------------------------------------------------------------------
# Per-category formatters
# ---------------------------------------------------------------------------


def _summarize_hardening(events: list[SecurityEvent]) -> str:
    """Summarize hardening category events."""
    lines = ["--- Hardening ---"]

    # Classify by mode in a single pass (mode lives in details.result)
    scans: list[SecurityEvent] = []
    reinforcements: list[SecurityEvent] = []
    for e in events:
        mode = _get_mode(e)
        if mode == "scan":
            scans.append(e)
        elif mode == "reinforce":
            reinforcements.append(e)

    scans_ok = sum(1 for e in scans if e.result == "succeeded")
    scans_fail = len(scans) - scans_ok
    lines.append(
        f"  Scans performed:  {len(scans)} (succeeded: {scans_ok}, failed: {scans_fail})"
    )

    if reinforcements:
        reinf_ok = sum(1 for e in reinforcements if e.result == "succeeded")
        reinf_fail = len(reinforcements) - reinf_ok
        lines.append(
            f"  Reinforcements:   {len(reinforcements)} "
            f"(succeeded: {reinf_ok}, failed: {reinf_fail})"
        )

    # Latest scan result details (prefer succeeded, fall back to latest failed)
    latest_scan = next((e for e in scans if e.result == "succeeded"), None)
    if latest_scan:
        result = _get_result(latest_scan)
        passed = result.get("passed", 0)
        total = result.get("total", 0)
        failures = result.get("failures", [])

        if total > 0:
            pct = passed / total * 100
            lines.append("")
            lines.append("  Latest scan result:")
            lines.append(f"    Compliance: {passed}/{total} rules passed ({pct:.1f}%)")

            if failures:
                lines.append(
                    "    Check system status using `agent-sec-cli harden --scan`"
                )
    elif scans:
        # All scans failed — show the latest error so users aren't left in the dark
        latest_error = scans[0]
        error_msg = _safe_details(latest_error).get("error", "unknown error")
        lines.append("")
        lines.append(f"  Latest scan failed: {error_msg}")

    return "\n".join(lines)


def _summarize_asset_verify(events: list[SecurityEvent]) -> str:
    """Summarize asset_verify category events."""
    lines = ["--- Asset Verification ---"]

    ok_count = 0
    latest: SecurityEvent | None = None
    for e in events:
        if e.result == "succeeded":
            ok_count += 1
            if latest is None:
                latest = e
    fail_count = len(events) - ok_count
    lines.append(
        f"  Verifications performed: {len(events)} "
        f"(succeeded: {ok_count}, failed: {fail_count})"
    )

    # Latest successful result
    if latest:
        result = _get_result(latest)
        passed = result.get("passed", 0)
        failed = result.get("failed", 0)
        lines.append("")
        lines.append("  Latest result:")
        lines.append(f"    {passed} passed, {failed} failed")
        if failed == 0:
            lines.append("    Integrity status: ALL CLEAR")
        else:
            lines.append("    Integrity status: FAILURES DETECTED")
            lines.append("    Check details using `agent-sec-cli verify`")

    return "\n".join(lines)


def _summarize_code_scan(events: list[SecurityEvent]) -> str:
    """Summarize code_scan category events."""
    lines = ["--- Code Scanning ---"]

    ok_count = 0
    verdict_counts: dict[str, int] = defaultdict(int)
    for e in events:
        if e.result == "succeeded":
            ok_count += 1
            result = _get_result(e)
            verdict = result.get("verdict", "unknown")
            verdict_counts[verdict] += 1
    fail_count = len(events) - ok_count
    lines.append(
        f"  Scans performed: {len(events)} (succeeded: {ok_count}, failed: {fail_count})"
    )

    if verdict_counts:
        parts = [f"{v}: {c}" for v, c in sorted(verdict_counts.items())]
        lines.append(f"  Verdict: {', '.join(parts)}")

    return "\n".join(lines)


def _summarize_sandbox(events: list[SecurityEvent]) -> str:
    """Summarize sandbox category events."""
    lines = ["--- Sandbox Guard ---"]
    total = len(events)
    lines.append(f"  Total interventions: {total}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Posture and footer
# ---------------------------------------------------------------------------


def _compute_posture(
    hardening_events: list[SecurityEvent],
    verify_events: list[SecurityEvent],
    time_label: str,
) -> str:
    """Compute overall security posture status.

    Status is determined solely by the latest hardening and asset_verify
    results.
    """

    needs_attention = False

    # --- Hardening (latest event) ---
    if hardening_events:
        latest_harden = hardening_events[0]  # events ordered desc
        if latest_harden.result == "failed":
            needs_attention = True
        elif latest_harden.result == "succeeded":
            result = _get_result(latest_harden)
            failures = result.get("failures", [])
            if failures:
                needs_attention = True

    # --- Asset Verification (latest event) ---
    if verify_events:
        latest_verify = verify_events[0]
        if latest_verify.result == "failed":
            needs_attention = True
        elif latest_verify.result == "succeeded":
            result = _get_result(latest_verify)
            if result.get("failed", 0) > 0:
                needs_attention = True

    # Determine status
    if needs_attention:
        status_line = "System Status: Needs attention \u26a0"
    else:
        status_line = "System Status: Good \u2713"

    lines = [
        f"Security Posture Summary ({time_label})",
        "",
        status_line,
    ]
    return "\n".join(lines)


def _build_footer(
    events: list[SecurityEvent],
    hardening_events: list[SecurityEvent],
) -> str:
    """Build footer with stats and suggested actions."""
    total = len(events)
    failed = sum(1 for e in events if e.result == "failed")

    # Find the newest event in O(n) instead of sorting
    newest = max(events, key=lambda e: e.timestamp) if events else None
    last_event_str = _time_since_last_event(newest) if newest else "N/A"

    lines = [
        "---",
        f"Total events: {total}  |  Failed: {failed}  |  Last event: {last_event_str}",
    ]

    # Suggested actions
    suggestions = _compute_suggestions(hardening_events)
    if suggestions:
        lines.append("")
        lines.append("Suggested actions:")
        for s in suggestions:
            lines.append(f"  {s}")

    return "\n".join(lines)


def _time_since_last_event(event: SecurityEvent) -> str:
    """Compute human-readable time since the given event."""
    try:
        event_dt = datetime.fromisoformat(event.timestamp)
        now = datetime.now(timezone.utc)
        delta = now - event_dt
        minutes = int(delta.total_seconds() / 60)
        if minutes < 1:
            return "just now"
        if minutes < 60:
            return f"{minutes} min ago"
        hours = minutes // 60
        if hours < 24:
            return f"{hours}h ago"
        days = hours // 24
        return f"{days}d ago"
    except (ValueError, TypeError):
        return "unknown"


def _compute_suggestions(hardening_events: list[SecurityEvent]) -> list[str]:
    """Generate actionable suggestions based on latest hardening event."""
    suggestions: list[str] = []

    if not hardening_events:
        return suggestions

    latest = hardening_events[0]  # newest-first after _group_by_category sort
    if latest.result == "succeeded":
        result = _get_result(latest)
        if result.get("failures"):
            suggestions.append("agent-sec-cli harden --reinforce    Fix failed rules")

    return suggestions
