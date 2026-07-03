"""Tests for the text formatter's rendering details.

These cover the source-excerpt underline (box-drawing, severity-colored), the
per-service column header that labels the leading line-number column, the
severity-then-line ordering of findings within a service, and the verdict line
(PASS sub-threshold breakdown, distinct ERROR for parse failures).
"""

from __future__ import annotations

import sys

import pytest

from compose_lint.formatters.text import (
    _COLORS,
    _LABEL_WIDTH,
    _PRESENCE_RULES,
    _RESET,
    _colorize,
    _display_width,
    _excerpt,
    _find_token,
    _sanitize,
    format_aggregate_summary,
    format_findings,
    format_summary,
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

    monkeypatch.setattr(sys, "stdout", _Tty())
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)


def _no_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force stdout to look like a non-terminal (e.g. a pipe)."""

    class _NoTty:
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr(sys, "stdout", _NoTty())


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
    assert _colorize("x", _RED) == "x"


def test_force_color_enables_color_through_a_pipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_tty(monkeypatch)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert _colorize("x", _RED) == f"{_RED}x{_RESET}"


def test_no_color_beats_force_color(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_color(monkeypatch)
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert _colorize("x", _RED) == "x"


def test_force_color_zero_does_not_force(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_tty(monkeypatch)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "0")
    assert _colorize("x", _RED) == "x"


# --- quiet mode -----------------------------------------------------------


def test_quiet_mode_is_one_line_per_finding(tmp_path) -> None:  # type: ignore[no-untyped-def]
    filepath = _write_compose(tmp_path)
    finding = Finding(
        "CL-0019",
        Severity.MEDIUM,
        "web",
        "Image 'nginx:1.0' is pinned to a tag but not a digest.",
        line=3,
        fix="Add a digest pin.",
        references=["https://example.test/ref"],
    )
    quiet = format_findings([finding], filepath, quiet=True)
    full = format_findings([finding], filepath)

    # The finding row survives; everything verbose does not.
    assert "CL-0019" in quiet
    assert "fix:" not in quiet
    assert "ref:" not in quiet
    assert "─" not in quiet  # no underline excerpt
    assert "│" not in quiet  # no source-line gutter
    # Sanity: full mode still renders all of them.
    assert "fix:" in full and "ref:" in full and "─" in full


def test_quiet_mode_drops_suppression_reason() -> None:
    finding = Finding(
        "CL-0001",
        Severity.CRITICAL,
        "web",
        "socket mounted",
        line=1,
        suppressed=True,
        suppression_reason="ticket-123 approved",
    )
    out = format_findings([finding], "compose.yml", quiet=True)
    assert "SUPPRESSED" in out
    assert "ticket-123" not in out
    assert "reason:" not in out


# --- aggregate summary pluralization --------------------------------------


def test_aggregate_summary_singular_file() -> None:
    out = format_aggregate_summary([([], "a.yml")])
    assert "1 file scanned" in out
    assert "1 files scanned" not in out


def test_aggregate_summary_plural_files() -> None:
    out = format_aggregate_summary([([], "a.yml"), ([], "b.yml")])
    assert "2 files scanned" in out


# --- T1: suppressed-row column alignment ----------------------------------


def test_suppressed_row_aligns_with_finding_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_tty(monkeypatch)  # plain output, no ANSI to skew column indexing
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    findings = [
        Finding("CL-0001", Severity.CRITICAL, "web", "active finding", line=2),
        Finding(
            "CL-0002", Severity.HIGH, "web", "muted finding", line=3, suppressed=True
        ),
    ]
    out = format_findings(findings, "compose.yml")
    rule_cols = [ln.index("CL-000") for ln in out.splitlines() if "CL-000" in ln]
    assert len(rule_cols) == 2
    assert rule_cols[0] == rule_cols[1]  # SUPPRESSED no longer shifts its row


def test_suppressed_marker_padded_to_label_width(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_tty(monkeypatch)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    finding = Finding("CL-0001", Severity.CRITICAL, "web", "x", line=1, suppressed=True)
    out = format_findings([finding], "compose.yml")
    assert f"SUPPRESSED{' ' * (_LABEL_WIDTH - len('SUPPRESSED'))}" in out


# --- T2: CL-0020 / CL-0021 are presence rules -----------------------------


def test_new_credential_rules_are_presence_rules() -> None:
    assert {"CL-0020", "CL-0021"} <= _PRESENCE_RULES


def test_cl0020_renders_source_excerpt(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "compose.yml"
    path.write_text(
        "services:\n  web:\n    environment:\n"
        "      AWS_SECRET_ACCESS_KEY: literalvalue\n",
        encoding="utf-8",
    )
    finding = Finding(
        "CL-0020",
        Severity.HIGH,
        "web",
        "Service has credential-shaped env key 'AWS_SECRET_ACCESS_KEY' "
        "with a literal value.",
        line=4,
    )
    out = format_findings([finding], str(path))
    assert "│" in out  # source gutter rendered
    assert "─" * len("AWS_SECRET_ACCESS_KEY") in out  # underline under the key


# --- T3: FORCE_COLOR truthiness -------------------------------------------


def test_force_color_false_disables(monkeypatch: pytest.MonkeyPatch) -> None:
    _force_color(monkeypatch)  # stdout looks like a tty (would colorize)
    monkeypatch.setenv("FORCE_COLOR", "false")
    assert _colorize("x", _RED) == "x"


def test_force_color_false_is_case_insensitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_color(monkeypatch)
    monkeypatch.setenv("FORCE_COLOR", "FALSE")
    assert _colorize("x", _RED) == "x"


def test_force_color_empty_string_enables(monkeypatch: pytest.MonkeyPatch) -> None:
    _no_tty(monkeypatch)  # pipe: default would be no color
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "")
    assert _colorize("x", _RED) == f"{_RED}x{_RESET}"


# --- T4: excerpt underline alignment --------------------------------------


def test_display_width_counts_wide_and_combining() -> None:
    assert _display_width("abc") == 3
    assert _display_width("你好") == 4  # two fullwidth code points
    assert _display_width("é") == 1  # 'e' + combining acute = one column


def test_find_token_prefers_boundary_over_substring() -> None:
    # The standalone "80" (after the colon), not the "80" inside "8080".
    assert _find_token("8080:80", "80") == 5
    # Falls back to the first match when the value is only ever a substring.
    assert _find_token("only-substr", "subst") == 5


def test_underline_targets_standalone_token(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "compose.yml"
    path.write_text(
        "services:\n  web:\n    ports:\n      - 8080:80\n", encoding="utf-8"
    )
    finding = Finding(
        "CL-0005", Severity.HIGH, "web", "Host port '80' is published.", line=4
    )
    out = format_findings([finding], str(path))
    raw = "      - 8080:80"
    # The underline sits under the standalone 80 (after the colon, col 13), not
    # the "80" inside 8080 (col 8); a col-8 underline would be " " * 8 + "──".
    expected_col = raw.index(":80") + 1
    assert expected_col == 13
    assert (" " * expected_col + "──") in out


# --- terminal-output sanitization (bidi / control-char injection) ---------

# Built via chr()/\x escapes so no invisible code points live in this file.
_RLO = chr(0x202E)  # RIGHT-TO-LEFT OVERRIDE
_ZWSP = chr(0x200B)  # ZERO WIDTH SPACE


def test_sanitize_escapes_bidi_and_control_chars() -> None:
    # A bidi override can visually reorder a malicious image tag to read benign.
    assert _sanitize(f"alpine{_RLO}3.18") == "alpine\\u202e3.18"
    # ESC (the ANSI introducer) and other C0 controls are neutralized.
    assert _sanitize("a\x1bb") == "a\\u001bb"
    # Zero-width characters can hide text.
    assert _sanitize(f"a{_ZWSP}b") == "a\\u200bb"


def test_sanitize_leaves_clean_text_unchanged() -> None:
    # ASCII, em-dash, and accented text must pass through untouched...
    clean = "postgres:9.6.9-alpine — café"
    assert _sanitize(clean) == clean
    # ...and tab is preserved so YAML excerpt indentation still lines up.
    assert _sanitize("\tindented") == "\tindented"


def test_format_findings_escapes_bidi_in_message() -> None:
    # An untrusted image name carrying a bidi override reaches the message.
    finding = Finding(
        "CL-0004",
        Severity.HIGH,
        "web",
        f"Service uses unpinned image 'nginx{_RLO}latest'.",
        line=3,
    )
    out = format_findings([finding], "compose.yml", quiet=True)
    assert _RLO not in out
    assert "\\u202e" in out


def test_excerpt_escapes_control_chars_read_off_disk() -> None:
    # The source excerpt is read straight off disk, bypassing the parser's
    # printable-character check — a raw ESC on the offending line would inject
    # an ANSI sequence into the terminal. It must be escaped instead.
    source_lines = ["services:", "  web:", "    image: nginx\x1b[31mhack"]
    out = "".join(_excerpt(3, source_lines, "image is bad", Severity.HIGH))
    assert "\x1b" not in out
    assert "\\u001b" in out


def test_format_summary_escapes_bidi_in_path() -> None:
    out = format_summary([], f"compose{_RLO}.yml")
    assert _RLO not in out
    assert "\\u202e" in out


def test_fix_dedup_keys_on_fix_not_rule_id() -> None:
    # Profile enrichment makes a rule's fix image-specific, so two services
    # flagged by the same rule can carry genuinely different guidance. The dedup
    # must not collapse the second into "(see fix above)" pointing at the first
    # service's (wrong-image) fix.
    findings = [
        Finding(
            "CL-0006",
            Severity.MEDIUM,
            "db",
            "caps not dropped",
            line=2,
            fix="cap_drop: [ALL]\nhint: cap_add: [CHOWN, DAC_OVERRIDE, SETGID, SETUID]",
        ),
        Finding(
            "CL-0006",
            Severity.MEDIUM,
            "proxy",
            "caps not dropped",
            line=6,
            fix="cap_drop: [ALL]\nprofile hint: cap_add: [NET_BIND_SERVICE]",
        ),
    ]
    out = format_findings(findings, "compose.yml")
    assert "CHOWN" in out
    assert "NET_BIND_SERVICE" in out  # the second, distinct hint is not collapsed
    assert "(see fix above)" not in out


def test_fix_dedup_collapses_identical_fixes() -> None:
    # Same rule + identical fix (no enrichment) still dedups to a single block.
    findings = [
        Finding(
            "CL-0003",
            Severity.MEDIUM,
            "web",
            "nnp",
            line=2,
            fix="- no-new-privileges:true",
        ),
        Finding(
            "CL-0003",
            Severity.MEDIUM,
            "api",
            "nnp",
            line=5,
            fix="- no-new-privileges:true",
        ),
    ]
    out = format_findings(findings, "compose.yml")
    assert out.count("- no-new-privileges:true") == 1
    assert "(see fix above)" in out
