"""Text formatter with colored terminal output."""

from __future__ import annotations

import re
import sys
from pathlib import Path

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

# Rules whose finding identifies a specific config value the user wrote, so a
# one-line source excerpt is rendered under the finding to show the offending
# value inline. Pure-absence rules (CL-0003/4/6/7) have nothing to underline —
# the violation is the absence — and are intentionally omitted. See
# docs/severity.md "Rule categories" for the full taxonomy.
_PRESENCE_RULES = frozenset(
    {
        "CL-0001",
        "CL-0002",
        "CL-0005",
        "CL-0008",
        "CL-0009",
        "CL-0010",
        "CL-0011",
        "CL-0012",
        "CL-0013",
        "CL-0014",
        "CL-0015",
        "CL-0016",
        "CL-0017",
        "CL-0018",
        "CL-0019",
    }
)

_QUOTED = re.compile(r"'([^']+)'")


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


def _read_source_lines(filepath: str) -> list[str] | None:
    try:
        return Path(filepath).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None


def _excerpt(line_num: int, source_lines: list[str], message: str) -> list[str]:
    """Render a one-line source excerpt, optionally with a caret.

    Returns 1 or 2 already-colorized strings. The caret is rendered only when
    the message contains a single-quoted substring that also appears in the
    source line — a heuristic that hits cleanly on rules whose message names
    the offending value (e.g. CL-0019 'postgres:9.6.9-alpine'), and falls
    back to the bare line otherwise.
    """
    if line_num < 1 or line_num > len(source_lines):
        return []
    raw = source_lines[line_num - 1].rstrip()
    line_label = str(line_num)
    pad = " " * len(line_label)
    bar = _colorize("│", _DIM)
    out = [f"{_colorize(line_label, _DIM)} {bar} {raw}"]

    match = _QUOTED.search(message)
    if match:
        needle = match.group(1)
        col = raw.find(needle)
        if col >= 0:
            caret = " " * col + "^" * len(needle)
            out.append(f"{pad} {bar} {_colorize(caret, _COLORS[Severity.HIGH])}")
    return out


def _service_sort_line(group: list[Finding]) -> int:
    return min((f.line for f in group if f.line is not None), default=10**9)


def format_findings(
    findings: list[Finding],
    filepath: str,
    *,
    verbose: bool = False,
) -> str:
    """Format findings as human-readable colored text grouped by file and service.

    The fix block and reference URL are printed only on the first occurrence
    of each rule id within a file; subsequent occurrences get a brief
    `(see fix above)` marker. ``verbose=True`` restores per-finding fix
    repetition for IDE tooling or local fix-it-now workflows.
    """
    if not findings:
        return ""

    source_lines = _read_source_lines(filepath)

    by_service: dict[str, list[Finding]] = {}
    for f in findings:
        by_service.setdefault(f.service, []).append(f)

    services_in_order = sorted(
        by_service.items(), key=lambda kv: _service_sort_line(kv[1])
    )

    out: list[str] = []
    out.append(_colorize(filepath, _BOLD))
    out.append("")

    seen_rules: set[str] = set()

    for service, group in services_in_order:
        svc_line = next((f.line for f in group if f.line is not None), None)
        header_suffix = f"  ({_colorize('line', _DIM)} {svc_line})" if svc_line else ""
        out.append(f"  {_colorize('service:', _DIM)} {service}{header_suffix}")

        for f in group:
            if f.suppressed:
                reason = f.suppression_reason or "disabled in .compose-lint.yml"
                line_label = str(f.line) if f.line else "?"
                out.append(
                    f"    {line_label.rjust(4)}  "
                    f"{_colorize('SUPPRESSED', _SUPPRESSED_COLOR)}  "
                    f"{_colorize(f.rule_id, _DIM)}  "
                    f"{_colorize(f.message, _SUPPRESSED_COLOR)}"
                )
                out.append(f"          {_colorize('reason:', _DIM)} {reason}")
                continue

            severity_label = f.severity.value.upper().ljust(_SEV_WIDTH)
            color = _COLORS.get(f.severity, "")
            line_label = str(f.line) if f.line else "?"

            already_shown = f.rule_id in seen_rules
            show_fix = verbose or not already_shown
            suffix = ""
            if already_shown and not verbose and (f.fix or f.references):
                suffix = f"   {_colorize('(see fix above)', _DIM)}"

            out.append(
                f"    {line_label.rjust(4)}  "
                f"{_colorize(severity_label, color)}  "
                f"{_colorize(f.rule_id, _DIM)}  "
                f"{f.message}{suffix}"
            )

            if (
                source_lines is not None
                and f.rule_id in _PRESENCE_RULES
                and f.line is not None
            ):
                for excerpt_line in _excerpt(f.line, source_lines, f.message):
                    out.append(f"          {excerpt_line}")

            if show_fix and f.fix:
                fix_lines = f.fix.split("\n")
                out.append(f"          {_colorize('fix:', _DIM)} {fix_lines[0]}")
                for fix_line in fix_lines[1:]:
                    out.append(f"               {fix_line}")
            if show_fix and f.references:
                out.append(f"          {_colorize('ref:', _DIM)} {f.references[0]}")

            seen_rules.add(f.rule_id)

        out.append("")

    return "\n".join(out).rstrip()


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
    """Format a combined summary line across all scanned files (multi-file runs).

    ``parse_error_count`` is the number of input files that could not be
    parsed; surfaced inline as ``N skipped (failed to parse)`` so multi-file
    runs make skipped files visible in the same place as the totals.
    """
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

    skipped_suffix = ""
    if parse_error_count:
        skipped_text = f"{parse_error_count} skipped (failed to parse)"
        skipped_suffix = f"  {sep}  {_colorize(skipped_text, _COLORS[Severity.HIGH])}"

    if total_issues == 0 and suppressed_total == 0:
        body = _colorize("no issues found", _GREEN)
        return f"{files_label}  {sep}  {body}{skipped_suffix}"

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
    result += skipped_suffix
    return result


def format_verdict(
    file_findings: list[tuple[list[Finding], str]],
    fail_on: Severity,
    parse_error_count: int = 0,
) -> str:
    """Return a pass/fail verdict line relative to the --fail-on threshold.

    A non-zero ``parse_error_count`` always forces a FAIL verdict, since the
    CLI exits 2 in that case regardless of finding severity.
    """
    failing = sum(
        1
        for findings, _ in file_findings
        for f in findings
        if not f.suppressed and f.severity >= fail_on
    )

    sep = _colorize("·", _DIM)

    if parse_error_count:
        skipped_word = "file" if parse_error_count == 1 else "files"
        skipped_text = f"{parse_error_count} {skipped_word} skipped (failed to parse)"
        if failing:
            word = "finding" if failing == 1 else "findings"
            return (
                f"{_colorize('✗ FAIL', _COLORS[Severity.HIGH])}  {sep}  "
                f"{failing} {word} at or above {fail_on.value}"
                f"  {sep}  {_colorize(skipped_text, _COLORS[Severity.HIGH])}"
            )
        return (
            f"{_colorize('✗ FAIL', _COLORS[Severity.HIGH])}  {sep}  "
            f"{_colorize(skipped_text, _COLORS[Severity.HIGH])}"
        )

    if failing == 0:
        return f"{_colorize('✓ PASS', _GREEN)}  {sep}  threshold: {fail_on.value}"

    word = "finding" if failing == 1 else "findings"
    return (
        f"{_colorize('✗ FAIL', _COLORS[Severity.HIGH])}  {sep}  "
        f"{failing} {word} at or above {fail_on.value}"
    )
