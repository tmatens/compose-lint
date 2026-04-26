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
_GREEN = "\033[32m"  # Green for pass / no issues
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

# All active severity labels are padded to this width so finding columns align.
_SEV_WIDTH = max(len(s.value) for s in Severity)  # len("critical") == 8


def _colorize(text: str, code: str) -> str:
    """Wrap text in ANSI color codes if stdout is a terminal."""
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{_RESET}"


def format_header(
    files: list[str],
    config_path: str | None,
    fail_on: Severity,
    version: str,
) -> str:
    """Format a branded run header showing the tool version and active parameters."""
    sep = _colorize("·", _DIM)
    config_str = config_path if config_path else "none"
    params = (
        f"files: {', '.join(files)}"
        f"  {sep}  config: {config_str}"
        f"  {sep}  fail-on: {fail_on.value}"
    )
    return f"{_colorize(f'compose-lint {version}', _BOLD)}\n{params}\n"


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

        severity_label = f.severity.value.upper().ljust(_SEV_WIDTH)
        color = _COLORS.get(f.severity, "")
        loc = f"{filepath}:{f.line}" if f.line else filepath

        lines.append(
            f"{_colorize(loc, _BOLD)}  "
            f"{_colorize(severity_label, color)}  "
            f"{_colorize(f.rule_id, _DIM)}  "
            f"{f.message}"
        )
        lines.append(f"  {_colorize('service:', _DIM)} {f.service}")

        if f.fix:
            fix_lines = f.fix.split("\n")
            lines.append(f"  {_colorize('fix:', _DIM)} {fix_lines[0]}")
            for fix_line in fix_lines[1:]:
                lines.append(f"       {fix_line}")

        if f.references:
            lines.append(f"  {_colorize('ref:', _DIM)} {f.references[0]}")

        lines.append("")

    return "\n".join(lines).rstrip()


def format_summary(
    findings: list[Finding],
    filepath: str,
) -> str:
    """Format a one-line summary of findings for a single file."""
    if not findings:
        return _colorize(f"{filepath}: no issues found", _GREEN)

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

    if not parts and not suppressed_count:
        return _colorize(f"{filepath}: no issues found", _GREEN)

    sep = _colorize("·", _DIM)
    body = ", ".join(parts) if parts else _colorize("0 issues", _DIM)
    if suppressed_count:
        supp_text = f"{suppressed_count} suppressed (not counted)"
        body += f"  {sep}  {_colorize(supp_text, _SUPPRESSED_COLOR)}"
    return f"{_colorize(filepath, _BOLD)}: {body}"


def format_aggregate_summary(
    file_findings: list[tuple[list[Finding], str]],
    parse_error_count: int = 0,
) -> str:
    """Format a combined summary line across all scanned files (multi-file runs)."""
    total_files = len(file_findings)
    by_severity: dict[str, int] = {}
    suppressed_total = 0

    for findings, _ in file_findings:
        for f in findings:
            if f.suppressed:
                suppressed_total += 1
            else:
                by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

    total_issues = sum(by_severity.values())
    files_label = _colorize(f"{total_files} files scanned", _BOLD)
    sep = _colorize("·", _DIM)

    if total_issues == 0 and suppressed_total == 0:
        result = f"{files_label}  {sep}  {_colorize('no issues found', _GREEN)}"
    else:
        parts = []
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            count = by_severity.get(sev.value, 0)
            if count:
                parts.append(_colorize(f"{count} {sev.value}", _COLORS[sev]))

        issue_word = "issue" if total_issues == 1 else "issues"
        breakdown = f" ({', '.join(parts)})" if parts else ""
        result = f"{files_label}  {sep}  {total_issues} {issue_word}{breakdown}"
        if suppressed_total:
            supp_text = f"{suppressed_total} suppressed (not counted)"
            result += f"  {sep}  {_colorize(supp_text, _SUPPRESSED_COLOR)}"

    if parse_error_count:
        file_word = "file" if parse_error_count == 1 else "files"
        skip_text = f"{parse_error_count} {file_word} skipped (parse errors)"
        result += f"  {sep}  {_colorize(skip_text, _COLORS[Severity.HIGH])}"
    return result


def format_verdict(
    file_findings: list[tuple[list[Finding], str]],
    fail_on: Severity,
    parse_error_count: int = 0,
) -> str:
    """Return a pass/fail verdict line relative to the --fail-on threshold.

    A non-zero parse_error_count forces the verdict to FAIL even when no
    finding crosses the threshold — partial scans must not look clean.
    """
    failing = sum(
        1
        for findings, _ in file_findings
        for f in findings
        if not f.suppressed and f.severity >= fail_on
    )

    sep = _colorize("·", _DIM)
    fail_label = _colorize("✗ FAIL", _COLORS[Severity.HIGH])

    parts: list[str] = []
    if failing:
        word = "finding" if failing == 1 else "findings"
        parts.append(f"{failing} {word} at or above {fail_on.value}")
    if parse_error_count:
        file_word = "file" if parse_error_count == 1 else "files"
        parts.append(f"{parse_error_count} {file_word} failed to parse")

    if not parts:
        return f"{_colorize('✓ PASS', _GREEN)}  {sep}  threshold: {fail_on.value}"

    return f"{fail_label}  {sep}  {f'  {sep}  '.join(parts)}"
