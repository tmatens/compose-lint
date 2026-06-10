"""Text formatter with colored terminal output."""

from __future__ import annotations

import os
import re
import sys
import unicodedata
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
_ERROR_COLOR = "\033[35m"  # Magenta — parse/usage error (exit 2), distinct from FAIL
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

# The marker shown in the severity column for a suppressed finding.
_SUPPRESSED_LABEL = "SUPPRESSED"

# All severity-column cells — severity labels and the SUPPRESSED marker — are
# padded to this width so the rule/message columns line up across every row,
# suppressed or not. "SUPPRESSED" (10) is wider than the longest severity
# ("critical", 8), so the column widens to it rather than letting suppressed
# rows push the later columns out of alignment.
_SEV_WIDTH = max(len(s.value) for s in Severity)  # len("critical") == 8
_LABEL_WIDTH = max(_SEV_WIDTH, len(_SUPPRESSED_LABEL))

# Rule ids are always CL-XXXX; pad the column header to match the finding rows.
_RULE_WIDTH = len("CL-XXXX")

# Render order for findings inside a service: highest severity first, then by
# line. The rank is derived from Severity's own ordering so it never drifts
# from the enum. JSON/SARIF keep the engine's line-only order — severity-first
# is a presentation choice that only applies to the grouped text view.
_SEV_ORDER = {sev: rank for rank, sev in enumerate(sorted(Severity, reverse=True))}


def _finding_sort_key(f: Finding) -> tuple[int, int]:
    return (_SEV_ORDER[f.severity], f.line if f.line is not None else 10**9)


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
        "CL-0020",
        "CL-0021",
    }
)

_QUOTED = re.compile(r"'([^']+)'")

# Code-point ranges (inclusive) that can spoof or corrupt terminal output when
# an untrusted string from the Compose file (image name, service name, env key,
# or a source line read straight off disk) is printed: C0/C1 controls —
# ANSI/escape-sequence injection, including the ESC and CSI introducers — plus
# DEL, and the bidirectional and zero-width formatting characters that visually
# reorder or hide text (e.g. U+202E RIGHT-TO-LEFT OVERRIDE rendering a malicious
# tag as a benign one). Built from hex so no invisible literals live in source;
# tab and newline are deliberately excluded so excerpt layout survives.
_UNSAFE_RANGES = (
    (0x00, 0x08),
    (0x0B, 0x1F),
    (0x7F, 0x9F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
)
_UNSAFE_OUTPUT_CHARS = re.compile(
    "[" + "".join(f"{chr(lo)}-{chr(hi)}" for lo, hi in _UNSAFE_RANGES) + "]"
)


def _sanitize(text: str) -> str:
    """Render terminal-unsafe code points as visible ``\\uXXXX`` escapes.

    Findings and source excerpts carry attacker-controlled text. The source
    excerpt in particular is read directly off disk (``_read_source_lines``),
    bypassing the parser's printable-character check, so a crafted Compose file
    could otherwise inject raw ANSI escapes or bidi overrides into a terminal
    or CI log. Clean ASCII/Unicode text is returned unchanged.
    """
    return _UNSAFE_OUTPUT_CHARS.sub(lambda m: f"\\u{ord(m.group()):04x}", text)


def _color_enabled() -> bool:
    """Decide whether to emit ANSI color, honoring the de-facto env standards.

    ``NO_COLOR`` (set to any non-empty value) disables color even on a TTY and
    wins over everything, per https://no-color.org. ``FORCE_COLOR``, when set,
    overrides TTY detection: ``0`` or ``false`` (case-insensitive) disables
    color, any other value — including the empty string — enables it, matching
    the chalk/supports-color convention. Otherwise color follows whether stdout
    is a terminal.
    """
    if os.environ.get("NO_COLOR"):
        return False
    force = os.environ.get("FORCE_COLOR")
    if force is not None:
        return force.lower() not in ("0", "false")
    return sys.stdout.isatty()


def _colorize(text: str, code: str) -> str:
    """Wrap text in ANSI color codes when color is enabled (see _color_enabled)."""
    if not _color_enabled():
        return text
    return f"{code}{text}{_RESET}"


def _display_width(text: str) -> int:
    """Terminal column width of ``text``.

    East-Asian wide/fullwidth code points count as 2 columns and zero-width
    combining marks as 0, so an underline lines up under CJK or accented text
    instead of drifting by the code-point/column mismatch. Uses the stdlib
    ``unicodedata`` rather than ``wcwidth`` to keep the runtime dependency
    surface at PyYAML only.
    """
    width = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


def _find_token(haystack: str, needle: str) -> int:
    """Index of ``needle`` in ``haystack`` at a token boundary, else first match.

    Plain ``str.find`` underlines the first substring hit, which mis-points when
    the value also appears inside a longer token (``80`` inside ``8080``) or as
    an earlier substring. Prefer an occurrence whose neighbors are not
    alphanumerics; fall back to the first match so a value that is only ever a
    substring still gets underlined rather than skipped.
    """

    def _word(c: str) -> bool:
        return c.isalnum() or c == "_"

    first = haystack.find(needle)
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx < 0:
            return first
        end = idx + len(needle)
        before = haystack[idx - 1] if idx > 0 else ""
        after = haystack[end] if end < len(haystack) else ""
        if not _word(before) and not _word(after):
            return idx
        start = idx + 1


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
        f"files: {', '.join(_sanitize(f) for f in files)}"
        f"  {sep}  config: {config_str}"
        f"  {sep}  fail-on: {fail_on.value}"
    )
    return f"{_colorize(f'compose-lint {version}', _BOLD)}\n{params}\n"


def _read_source_lines(filepath: str) -> list[str] | None:
    try:
        return Path(filepath).read_text(encoding="utf-8").splitlines()
    except OSError:
        return None


def _excerpt(
    line_num: int,
    source_lines: list[str],
    message: str,
    severity: Severity,
) -> list[str]:
    """Render a one-line source excerpt, optionally with an underline.

    Returns 1 or 2 already-colorized strings. The underline is a box-drawing
    rule (─) tinted with the finding's own ``severity`` color, so the marker
    reads as a deliberate pointer rather than a red error squiggle. It is
    rendered only when the message contains a single-quoted substring that
    also appears in the source line — a heuristic that hits cleanly on rules
    whose message names the offending value (e.g. CL-0019
    'postgres:9.6.9-alpine'), and falls back to the bare line otherwise.
    """
    if line_num < 1 or line_num > len(source_lines):
        return []
    raw = _sanitize(source_lines[line_num - 1].rstrip())
    line_label = str(line_num)
    pad = " " * len(line_label)
    bar = _colorize("│", _DIM)
    out = [f"{_colorize(line_label, _DIM)} {bar} {raw}"]

    match = _QUOTED.search(message)
    if match:
        needle = match.group(1)
        col = _find_token(raw, needle)
        if col >= 0:
            indent = _display_width(raw[:col])
            underline = " " * indent + "─" * _display_width(needle)
            color = _COLORS.get(severity, "")
            out.append(f"{pad} {bar} {_colorize(underline, color)}")
    return out


def _service_sort_line(group: list[Finding]) -> int:
    return min((f.line for f in group if f.line is not None), default=10**9)


def format_findings(
    findings: list[Finding],
    filepath: str,
    *,
    verbose: bool = False,
    quiet: bool = False,
) -> str:
    """Format findings as human-readable colored text grouped by file and service.

    The fix block and reference URL are printed only on the first occurrence
    of each rule id within a file; subsequent occurrences get a brief
    `(see fix above)` marker. ``verbose=True`` restores per-finding fix
    repetition for IDE tooling or local fix-it-now workflows. ``quiet=True``
    does the opposite — one line per finding, dropping the fix block,
    reference URL, source excerpt, and suppression reason — for CI and repeat
    users. The two are mutually exclusive at the CLI layer.
    """
    if not findings:
        return ""

    source_lines = None if quiet else _read_source_lines(filepath)

    by_service: dict[str, list[Finding]] = {}
    for f in findings:
        by_service.setdefault(f.service, []).append(f)

    services_in_order = sorted(
        by_service.items(), key=lambda kv: _service_sort_line(kv[1])
    )

    out: list[str] = []
    out.append(_colorize(_sanitize(filepath), _BOLD))
    out.append("")

    seen_rules: set[str] = set()

    for service, group in services_in_order:
        svc_line = next((f.line for f in group if f.line is not None), None)
        header_suffix = f"  ({_colorize('line', _DIM)} {svc_line})" if svc_line else ""
        out.append(
            f"  {_colorize('service:', _DIM)} {_sanitize(service)}{header_suffix}"
        )
        out.append(
            _colorize(
                f"    {'line'.rjust(4)}  "
                f"{'severity'.ljust(_LABEL_WIDTH)}  "
                f"{'rule'.ljust(_RULE_WIDTH)}  message",
                _DIM,
            )
        )

        for f in sorted(group, key=_finding_sort_key):
            if f.suppressed:
                reason = f.suppression_reason or "disabled in .compose-lint.yml"
                line_label = str(f.line) if f.line else "?"
                marker = _colorize(
                    _SUPPRESSED_LABEL.ljust(_LABEL_WIDTH), _SUPPRESSED_COLOR
                )
                out.append(
                    f"    {line_label.rjust(4)}  "
                    f"{marker}  "
                    f"{_colorize(f.rule_id, _DIM)}  "
                    f"{_colorize(_sanitize(f.message), _SUPPRESSED_COLOR)}"
                )
                if not quiet:
                    out.append(
                        f"          {_colorize('reason:', _DIM)} {_sanitize(reason)}"
                    )
                continue

            severity_label = f.severity.value.upper().ljust(_LABEL_WIDTH)
            color = _COLORS.get(f.severity, "")
            line_label = str(f.line) if f.line else "?"
            message = _sanitize(f.message)

            already_shown = f.rule_id in seen_rules
            show_fix = not quiet and (verbose or not already_shown)
            suffix = ""
            if not quiet and already_shown and not verbose and (f.fix or f.references):
                suffix = f"   {_colorize('(see fix above)', _DIM)}"

            out.append(
                f"    {line_label.rjust(4)}  "
                f"{_colorize(severity_label, color)}  "
                f"{_colorize(f.rule_id, _DIM)}  "
                f"{message}{suffix}"
            )

            if (
                source_lines is not None
                and f.rule_id in _PRESENCE_RULES
                and f.line is not None
            ):
                for excerpt_line in _excerpt(f.line, source_lines, message, f.severity):
                    out.append(f"          {excerpt_line}")

            if show_fix and f.fix:
                fix_lines = _sanitize(f.fix).split("\n")
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
    filepath = _sanitize(filepath)
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
    file_word = "file" if total_files == 1 else "files"
    files_label = _colorize(f"{total_files} {file_word} scanned", _BOLD)
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


def _severity_breakdown(
    file_findings: list[tuple[list[Finding], str]],
) -> list[str]:
    """Colored ``N severity`` parts for all non-suppressed findings, high to low.

    Matches the house style of the per-file and aggregate summaries so the
    verdict reads consistently with the lines above it.
    """
    by_severity: dict[Severity, int] = {}
    for findings, _ in file_findings:
        for f in findings:
            if not f.suppressed:
                by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    parts = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        count = by_severity.get(sev, 0)
        if count:
            parts.append(_colorize(f"{count} {sev.value}", _COLORS[sev]))
    return parts


def format_verdict(
    file_findings: list[tuple[list[Finding], str]],
    fail_on: Severity,
    parse_error_count: int = 0,
) -> str:
    """Return the verdict line, matching the CLI's three exit-code outcomes.

    A non-zero ``parse_error_count`` (exit 2) yields a distinct ``⚠ ERROR``
    verdict, kept separate from the ``✗ FAIL`` (exit 1) threshold breach so a
    reader can tell a broken-input problem from an insecure-config one. A
    passing run that still has sub-threshold findings names them, so the
    ``✓ PASS`` line does not read as "nothing found".
    """
    failing = sum(
        1
        for findings, _ in file_findings
        for f in findings
        if not f.suppressed and f.severity >= fail_on
    )

    sep = _colorize("·", _DIM)

    if parse_error_count:
        file_word = "file" if parse_error_count == 1 else "files"
        parsed_text = f"{parse_error_count} {file_word} could not be parsed"
        error_label = _colorize("⚠ ERROR", _ERROR_COLOR)
        result = f"{error_label}  {sep}  {_colorize(parsed_text, _ERROR_COLOR)}"
        if failing:
            word = "finding" if failing == 1 else "findings"
            result += f"  {sep}  {failing} {word} at or above {fail_on.value}"
        return result

    if failing == 0:
        verdict = f"{_colorize('✓ PASS', _GREEN)}  {sep}  threshold: {fail_on.value}"
        below = _severity_breakdown(file_findings)
        if below:
            verdict += f"  {sep}  below: {', '.join(below)}"
        return verdict

    word = "finding" if failing == 1 else "findings"
    return (
        f"{_colorize('✗ FAIL', _COLORS[Severity.HIGH])}  {sep}  "
        f"{failing} {word} at or above {fail_on.value}"
    )
