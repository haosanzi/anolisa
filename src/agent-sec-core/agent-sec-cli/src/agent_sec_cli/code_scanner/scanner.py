import time
from typing import List, Optional

from agent_sec_cli.code_scanner.engine.code_extractor import (
    extract_inline_code,
)
from agent_sec_cli.code_scanner.engine.regex_engine import run_regex_rules
from agent_sec_cli.code_scanner.models import (
    Finding,
    Language,
    ScanResult,
    Severity,
    Verdict,
)
from agent_sec_cli.code_scanner.rules.rule_loader import load_rules

_SEVERITY_ORDER = {
    Severity.WARN: 0,
    Severity.DENY: 1,
}


def _compute_verdict(findings: List[Finding]) -> Verdict:
    """Return the verdict based on the highest severity across all findings."""
    if not findings:
        return Verdict.PASS
    max_severity = max(
        findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 0)
    ).severity
    if max_severity == Severity.DENY:
        return Verdict.DENY
    return Verdict.WARN


def _build_summary(findings: List[Finding], language: Language) -> str:
    """Build a human-readable summary string."""
    if not findings:
        return f"No issues found in {language.value} code"
    rule_ids = [f.rule_id for f in findings]
    return f"Detected {len(findings)} issue(s) in {language.value} code: {', '.join(rule_ids)}"


def scan(
    code: str, language: Language, *, rules: Optional[List[str]] = None
) -> ScanResult:
    """Scan *code* written in *language* for security issues.

    This is the sole public entry point of the code_scanner module.

    Args:
        code: The source code to scan.
        language: The programming language of the code.
        rules: Optional list of rule_ids to enable. When ``None`` (default),
            all rules for the given language are used.
    """
    start = time.monotonic_ns()
    try:
        # For bash code, attempt inline extraction to detect nested python etc.
        if language == Language.BASH:
            inline = extract_inline_code(code)
            if inline is not None:
                code, language = inline

        all_rules = load_rules(language)
        if rules is not None:
            enabled = set(rules)
            all_rules = [r for r in all_rules if r.rule_id in enabled]
        findings = run_regex_rules(code, all_rules, language)
        verdict = _compute_verdict(findings)
        summary = _build_summary(findings, language)
        elapsed = (time.monotonic_ns() - start) // 1_000_000
        return ScanResult(
            ok=True,
            verdict=verdict,
            summary=summary,
            findings=findings,
            language=language,
            elapsed_ms=elapsed,
        )
    except Exception:
        elapsed = (time.monotonic_ns() - start) // 1_000_000
        return ScanResult(
            ok=False,
            verdict=Verdict.ERROR,
            summary="scan error",
            findings=[],
            language=language,
            elapsed_ms=elapsed,
        )
