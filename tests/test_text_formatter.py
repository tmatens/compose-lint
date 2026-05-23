"""Tests for the text formatter's rendering details.

These cover the source-excerpt underline (box-drawing, severity-colored), the
per-service column header that labels the leading line-number column, the
severity-then-line ordering of findings within a service, and the verdict line
(PASS sub-threshold breakdown, distinct ERROR for parse failures).
"""

from __future__ import annotations

import pytest

import compose_lint.formatters.text as text
from compose_lint.formatters.text import (
    _COLORS,
    _RESET,
    format_findings,
    format_verdict,
)
from compose_lint.models import Finding, Severity


def _force_color(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make _colorize emit ANSI codes regardless of the test's real stdout.

    Also clears NO_COLOR/FORCE_COLOR so the color-on baseline is deterministic
    no matter what the test runner's environment sets.
    """

    class _Tty:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(text.sys, "stdout", _Tty())
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)


def _no_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force stdout to look like a non-terminal (e.g. a pipe)."""

    class _NoTty:
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr(text.sys, "stdout", _NoTty())


def _image_finding(severity: Severity) -> Finding:
    """A presence-rule finding whose message quotes a value on line 3."""
    return Finding(
        rule_id="CL-0019",
        severity=severity,
        service="web",
        message="Image 'nginx:1.0' is pinned to a tag but not a digest.",
        line=3,
    )


def _write_compose(tmp_path) -> str:  # type: ignore[no-untyped-def]
    path = tmp_path / "compose.yml"
    path.write_text("services:\n  web:\n    image: nginx:1.0\n", encoding="utf-8")
    return str(path)


def test_underline_uses_box_drawing_not_caret(tmp_path) -> None:  # type: ignore[no-untyped-def]
    filepath = _write_compose(tmp_path)
    out = format_findings([_image_finding(Severity.MEDIUM)], filepath)
    assert "─" * len("nginx:1.0") in out
    assert "^" not in out


def test_every_severity_has_a_color() -> None:
    for severity in Severity:
        assert severity in _COLORS, f"{severity} has no color"


@pytest.mark.parametrize("severity", list(Severity))
def test_underline_color_matches_severity_label(
    severity: Severity,
    tmp_path,  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_color(monkeypatch)
    filepath = _write_compose(tmp_path)
    out = format_findings([_image_finding(severity)], filepath)

    color = _COLORS[severity]
    # The severity label carries the severity color.
    assert f"{color}{severity.value.upper()}" in out
    # The underline carries the *same* color, positioned under the value.
    col = "    image: nginx:1.0".find("nginx:1.0")
    underline = " " * col + "─" * len("nginx:1.0")
    assert f"{color}{underline}{_RESET}" in out


def test_findings_within_service_sort_by_severity_then_line() -> None:
    # Same service, deliberately supplied in a non-severity, non-line order.
    findings = [
        Finding("CL-0003", Severity.MEDIUM, "web", "medium on line 2", line=2),
        Finding("CL-0001", Severity.CRITICAL, "web", "critical on line 9", line=9),
        Finding("CL-0005", Severity.HIGH, "web", "high on line 5", line=5),
        Finding("CL-0007", Severity.MEDIUM, "web", "medium on line 1", line=1),
    ]
    out = format_findings(findings, "compose.yml")
    order = [
        ln.split()[2]
        for ln in out.splitlines()
        if ln.strip()[:1].isdigit() and "CL-" in ln
    ]
    # CRITICAL, then HIGH, then the two MEDIUMs ascending by line (1 before 2).
    assert order == ["CL-0001", "CL-0005", "CL-0007", "CL-0003"]


def test_column_header_labels_the_line_column(tmp_path) -> None:  # type: ignore[no-untyped-def]
    filepath = _write_compose(tmp_path)
    out = format_findings([_image_finding(Severity.MEDIUM)], filepath)
    # The header row names every column so the leading number reads as a line.
    assert "line" in out
    assert "severity" in out
    assert "rule" in out
    header_line = next(ln for ln in out.splitlines() if ln.strip().startswith("line"))
    assert header_line.split() == ["line", "severity", "rule", "message"]


# --- verdict line ---------------------------------------------------------


def _bundle(*findings: Finding) -> list[tuple[list[Finding], str]]:
    return [(list(findings), "compose.yml")]


def test_pass_names_sub_threshold_findings() -> None:
    findings = [
        Finding("CL-0005", Severity.HIGH, "web", "h", line=1),
        Finding("CL-0003", Severity.MEDIUM, "web", "m", line=2),
        Finding("CL-0003", Severity.MEDIUM, "db", "m", line=3),
    ]
    verdict = format_verdict(_bundle(*findings), Severity.CRITICAL)
    assert verdict.startswith("✓ PASS")
    assert "threshold: critical" in verdict
    assert "below:" in verdict
    assert "1 high" in verdict
    assert "2 medium" in verdict


def test_clean_pass_has_no_breakdown() -> None:
    verdict = format_verdict([], Severity.HIGH)
    assert verdict == "✓ PASS  ·  threshold: high"
    assert "below" not in verdict


def test_parse_error_is_error_not_fail() -> None:
    verdict = format_verdict([], Severity.HIGH, parse_error_count=1)
    assert verdict.startswith("⚠ ERROR")
    assert "could not be parsed" in verdict
    assert "FAIL" not in verdict


def test_parse_error_pluralizes_and_keeps_findings() -> None:
    findings = [Finding("CL-0001", Severity.CRITICAL, "web", "c", line=1)]
    verdict = format_verdict(_bundle(*findings), Severity.HIGH, parse_error_count=2)
    assert verdict.startswith("⚠ ERROR")
    assert "2 files could not be parsed" in verdict
    assert "1 finding at or above high" in verdict


def test_threshold_breach_still_fails() -> None:
    findings = [Finding("CL-0001", Severity.CRITICAL, "web", "c", line=1)]
    verdict = format_verdict(_bundle(*findings), Severity.HIGH)
    assert verdict.startswith("✗ FAIL")
    assert "1 finding at or above high" in verdict


# --- color env handling (NO_COLOR / FORCE_COLOR) --------------------------

_RED = _COLORS[Severity.HIGH]


def test_no_color_disables_color_even_on_a_tty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_color(monkeypatch)  # stdout looks like a tty
    monkeypatch.setenv("NO_COLOR", "1")
    assert text._colorize("x", _RED) == "x"


def test_force_color_enables_color_through_a_pipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_tty(monkeypatch)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert text._colorize("x", _RED) == f"{_RED}x{_RESET}"


def test_no_color_beats_force_color(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_color(monkeypatch)
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert text._colorize("x", _RED) == "x"


def test_force_color_zero_does_not_force(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_tty(monkeypatch)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "0")
    assert text._colorize("x", _RED) == "x"
