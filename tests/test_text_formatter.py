"""Tests for the text formatter's rendering details.

These cover the source-excerpt underline (box-drawing, severity-colored), the
per-service column header that labels the leading line-number column, and the
severity-then-line ordering of findings within a service.
"""

from __future__ import annotations

import pytest

import compose_lint.formatters.text as text
from compose_lint.formatters.text import _COLORS, _RESET, format_findings
from compose_lint.models import Finding, Severity


def _force_color(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make _colorize emit ANSI codes regardless of the test's real stdout."""

    class _Tty:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(text.sys, "stdout", _Tty())


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
