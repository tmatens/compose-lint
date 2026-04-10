"""Text formatter with colored terminal output."""

from __future__ import annotations

import sys

from compose_lint.models import Finding, Severity

_COLORS = {
    Severity.CRITICAL: "\033[1;31m",  # Bold red
    Severity.HIGH: "\033[31m",  # Red
    Severity.MEDIUM: "\033[33m",  # Yellow
    Severity.LOW: "\033[36m",  # Cyan
}
_SUPPRESSED_COLOR = "\033[90m"  # Gray
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _colorize(text: str, code: str) -> str:
    """Wrap text in ANSI color codes if stdout is a terminal."""
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{_RESET}"


def format_findings(findings: list[Finding], filepath: str) -> str:
    """Format findings as human-readable colored text."""
    if not findings:
        return ""

    lines: list[str] = []

    for f in findings:
        if f.suppressed:
            loc = f"{filepath}:{f.line}" if f.line else filepath
            reason = f.suppression_reason or "disabled in .compose-lint.yml"
            lines.append(
                f"{_colorize(loc, _DIM)}  "
                f"{_colorize('SUPPRESSED', _SUPPRESSED_COLOR)}  "
                f"{_colorize(f.rule_id, _DIM)}  "
                f"{_colorize(f.message, _SUPPRESSED_COLOR)}"
            )
            lines.append(f"  {_colorize('service:', _DIM)} {f.service}")
            lines.append(f"  {_colorize('reason:', _DIM)} {reason}")
            lines.append("")
            continue

        severity_label = f.severity.value.upper()
        color = _COLORS.get(f.severity, "")

        # Location
        loc = f"{filepath}:{f.line}" if f.line else filepath

        # Main finding line
        lines.append(
            f"{_colorize(loc, _BOLD)}  "
            f"{_colorize(severity_label, color)}  "
            f"{_colorize(f.rule_id, _DIM)}  "
            f"{f.message}"
        )

        # Service name
        lines.append(f"  {_colorize('service:', _DIM)} {f.service}")

        # Fix guidance
        if f.fix:
            fix_lines = f.fix.split("\n")
            lines.append(f"  {_colorize('fix:', _DIM)} {fix_lines[0]}")
            for fix_line in fix_lines[1:]:
                lines.append(f"       {fix_line}")

        # References
        if f.references:
            lines.append(f"  {_colorize('ref:', _DIM)} {f.references[0]}")

        lines.append("")  # Blank line between findings

    return "\n".join(lines).rstrip()


def format_summary(
    findings: list[Finding],
    filepath: str,
) -> str:
    """Format a one-line summary of findings."""
    if not findings:
        return _colorize(f"{filepath}: no issues found", _DIM)

    by_severity: dict[str, int] = {}
    suppressed_count = 0
    for f in findings:
        if f.suppressed:
            suppressed_count += 1
        else:
            label = f.severity.value
            by_severity[label] = by_severity.get(label, 0) + 1

    parts = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        count = by_severity.get(sev.value, 0)
        if count:
            color = _COLORS.get(sev, "")
            parts.append(_colorize(f"{count} {sev.value}", color))

    if suppressed_count:
        parts.append(_colorize(f"{suppressed_count} suppressed", _SUPPRESSED_COLOR))

    if not parts:
        return _colorize(f"{filepath}: no issues found", _DIM)

    return f"{_colorize(filepath, _BOLD)}: {', '.join(parts)}"
