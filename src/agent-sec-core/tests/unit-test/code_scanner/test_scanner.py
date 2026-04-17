from unittest.mock import patch

from agent_sec_cli.code_scanner.errors import (
    CodeScanError,
    ErrRegexCompile,
    ErrRuleFileNotFound,
    ErrRuleYamlParse,
)
from agent_sec_cli.code_scanner.models import Language, Verdict
from agent_sec_cli.code_scanner.scanner import scan


def test_scan_detection(scan_test_case: tuple) -> None:
    """Parametrised four-tuple test: (code, language, rule_id, expected_count)."""
    code, language, rule_id, expected_count = scan_test_case
    result = scan(code, language, rules=[rule_id])
    assert result.ok is True
    assert len(result.findings) == expected_count, (
        f"Expected {expected_count} finding(s) for rule '{rule_id}' on: {code!r}, "
        f"got {len(result.findings)}: {[f.rule_id for f in result.findings]}"
    )


def test_scan_pass_verdict() -> None:
    """When no rule matches, verdict should be PASS."""
    result = scan("echo hello", Language.BASH)
    assert result.ok is True
    assert result.verdict == Verdict.PASS
    assert result.findings == []


def test_scan_warn_verdict() -> None:
    """A matching warn-severity rule should produce WARN verdict."""
    result = scan("rm -rf /tmp/test", Language.BASH)
    assert result.ok is True
    assert result.verdict == Verdict.WARN
    assert len(result.findings) > 0
    assert all(f.severity.value == "warn" for f in result.findings)


def test_scan_result_schema_fields() -> None:
    """ScanResult must expose all required fields."""
    result = scan("ls -la", Language.BASH)
    assert result.language == Language.BASH
    assert isinstance(result.elapsed_ms, int)
    assert result.elapsed_ms >= 0


def test_scan_evidence_is_list() -> None:
    """evidence field must be a list of strings."""
    result = scan("rm -rf /a && rm -r /b", Language.BASH)
    assert result.ok is True
    for finding in result.findings:
        assert isinstance(finding.evidence, list)
        assert len(finding.evidence) >= 1
        assert all(isinstance(e, str) for e in finding.evidence)


def test_scan_unknown_language_no_rules() -> None:
    """Scanning with a language that has no rule files still returns ok=True, PASS."""
    result = scan("print('hello')", Language.PYTHON)
    assert result.ok is True
    assert result.verdict == Verdict.PASS
    assert result.findings == []


# -- Error handling tests --


def test_scan_empty_code_returns_error() -> None:
    """Empty input should return ERROR verdict with ErrInputEmpty message."""
    result = scan("", Language.BASH)
    assert result.ok is False
    assert result.verdict == Verdict.ERROR
    assert result.summary == "scan error: empty input code"


def test_scan_whitespace_only_returns_error() -> None:
    """Whitespace-only input should return ERROR verdict."""
    result = scan("   \n\t  ", Language.BASH)
    assert result.ok is False
    assert result.verdict == Verdict.ERROR
    assert result.summary == "scan error: empty input code"


@patch("agent_sec_cli.code_scanner.scanner.load_rules")
def test_scan_rule_file_not_found(mock_load: object) -> None:
    mock_load.side_effect = ErrRuleFileNotFound("/missing/path")  # type: ignore[attr-defined]
    result = scan("echo hello", Language.BASH)
    assert result.ok is False
    assert result.verdict == Verdict.ERROR
    assert "rule file not found" in result.summary


@patch("agent_sec_cli.code_scanner.scanner.load_rules")
def test_scan_rule_yaml_parse_error(mock_load: object) -> None:
    mock_load.side_effect = ErrRuleYamlParse()  # type: ignore[attr-defined]
    result = scan("echo hello", Language.BASH)
    assert result.ok is False
    assert result.verdict == Verdict.ERROR
    assert "rule file YAML parse error" in result.summary


@patch("agent_sec_cli.code_scanner.scanner.run_regex_rules")
@patch("agent_sec_cli.code_scanner.scanner.load_rules", return_value=[])
def test_scan_regex_compile_error(mock_load: object, mock_run: object) -> None:
    mock_run.side_effect = ErrRegexCompile("bad pattern")  # type: ignore[attr-defined]
    result = scan("echo hello", Language.BASH)
    assert result.ok is False
    assert result.verdict == Verdict.ERROR
    assert "regex compile failed" in result.summary


@patch("agent_sec_cli.code_scanner.scanner.load_rules")
def test_scan_memory_error(mock_load: object) -> None:
    mock_load.side_effect = MemoryError()  # type: ignore[attr-defined]
    result = scan("echo hello", Language.BASH)
    assert result.ok is False
    assert result.verdict == Verdict.ERROR
    assert result.summary == "scan error: engine resource exhausted"


@patch("agent_sec_cli.code_scanner.scanner.load_rules")
def test_scan_unexpected_exception(mock_load: object) -> None:
    mock_load.side_effect = RuntimeError("boom")  # type: ignore[attr-defined]
    result = scan("echo hello", Language.BASH)
    assert result.ok is False
    assert result.verdict == Verdict.ERROR
    assert result.summary == "scan error: internal error"


def test_scan_normal_no_error_summary() -> None:
    """Normal scan should not have 'scan error' in summary."""
    result = scan("echo hello", Language.BASH)
    assert result.ok is True
    assert "scan error" not in result.summary
