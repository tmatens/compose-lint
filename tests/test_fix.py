"""Tests for the fix edit engine (ADR-014)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from compose_lint.engine import run_rules
from compose_lint.fix import (
    OverlappingEditError,
    apply_edits,
    block_span,
    collect_edits,
    delete_lines,
    first_child_indent,
    has_anchor_child,
    has_merge_key_child,
    is_anchored_or_merged,
    line_indent,
    opens_block_body,
    render_file_diff,
)
from compose_lint.models import TextEdit
from compose_lint.parser import load_compose

if TYPE_CHECKING:
    from pathlib import Path


def _findings_for(tmp_path: Path, source: str) -> tuple[list, dict, dict, str]:
    """Parse ``source``, lint it, and return (findings, data, lines, text)."""
    path = tmp_path / "docker-compose.yml"
    path.write_text(source, encoding="utf-8")
    data, lines = load_compose(path)
    text = path.read_text(encoding="utf-8")
    findings = run_rules(data, lines)
    return findings, data, lines, text


def test_no_edits_returns_text_unchanged() -> None:
    text = "services:\n  web:\n    image: nginx\n"
    assert apply_edits(text, []) == text


def test_pure_insertion() -> None:
    text = "a: 1\nb: 2\n"
    # Zero-width region at the start of line 3 (just past the final newline).
    edit = TextEdit(3, 1, 3, 1, "c: 3\n")
    assert apply_edits(text, [edit]) == "a: 1\nb: 2\nc: 3\n"


def test_pure_deletion_removes_whole_line() -> None:
    text = "a: 1\nbad: x\nb: 2\n"
    # Delete line 2 by replacing [line2:col1, line3:col1) with nothing.
    edit = TextEdit(2, 1, 3, 1, "")
    assert apply_edits(text, [edit]) == "a: 1\nb: 2\n"


def test_in_scalar_replacement() -> None:
    text = "ports:\n  - 0.0.0.0:8080:80\n"
    # Replace the seven characters "0.0.0.0" (cols 5-11) on line 2.
    edit = TextEdit(2, 5, 2, 12, "127.0.0.1")
    assert apply_edits(text, [edit]) == "ports:\n  - 127.0.0.1:8080:80\n"


def test_multiple_non_overlapping_edits() -> None:
    text = "a: 1\nb: 2\n"
    edits = [
        TextEdit(2, 1, 2, 1, "x\n"),
        TextEdit(3, 1, 3, 1, "y\n"),
    ]
    # Order of the input list must not matter; result is deterministic.
    assert apply_edits(text, edits) == "a: 1\nx\nb: 2\ny\n"
    assert apply_edits(text, list(reversed(edits))) == "a: 1\nx\nb: 2\ny\n"


def test_adjacent_edits_are_allowed() -> None:
    text = "abcdef\n"
    edits = [
        TextEdit(1, 1, 1, 3, "AB"),  # replaces "ab"
        TextEdit(1, 3, 1, 5, "CD"),  # replaces "cd", begins where the prior ends
    ]
    assert apply_edits(text, edits) == "ABCDef\n"


def test_overlapping_edits_raise() -> None:
    text = "abcdef\n"
    edits = [
        TextEdit(1, 1, 1, 4, "X"),  # covers cols 1-3
        TextEdit(1, 2, 1, 5, "Y"),  # starts inside the first region
    ]
    with pytest.raises(OverlappingEditError):
        apply_edits(text, edits)


def test_caveat_field_is_preserved() -> None:
    edit = TextEdit(1, 1, 1, 1, "read_only: true\n", caveat="breaks writers")
    assert edit.caveat == "breaks writers"
    # A caveat does not change how the edit is applied.
    assert apply_edits("x: 1\n", [edit]) == "read_only: true\nx: 1\n"


# --- Text-shaping helpers -------------------------------------------------


def test_line_indent_counts_leading_spaces() -> None:
    assert line_indent("foo: 1\n") == 0
    assert line_indent("    foo: 1\n") == 4
    assert line_indent("  - item\n") == 2
    assert line_indent("\n") == 0


def test_opens_block_body_true_for_bare_key_or_comment() -> None:
    assert opens_block_body("web:\n")
    assert opens_block_body("  web:  # frontend\n")


def test_opens_block_body_false_for_inline_flow_anchor_alias() -> None:
    assert not opens_block_body("web: nginx\n")  # inline value
    assert not opens_block_body("web: {image: nginx}\n")  # flow mapping
    assert not opens_block_body("web: &anchor\n")  # anchor
    assert not opens_block_body("web: *alias\n")  # alias
    assert not opens_block_body("just text\n")  # no colon


def test_first_child_indent() -> None:
    lines = ["web:\n", "  image: nginx\n", "  ports:\n", "    - 80\n"]
    assert first_child_indent(lines, 1) == 2
    # No deeper line after the key -> no children.
    assert first_child_indent(["web:\n", "db:\n"], 1) is None
    # Blank lines are skipped when locating the first child.
    assert first_child_indent(["web:\n", "\n", "    image: x\n"], 1) == 4


def test_first_child_indent_compact_sequence() -> None:
    # A block sequence value may sit at its key's own indent (compact style);
    # those `- item` lines are still children.
    compact = ["security_opt:\n", "- seccomp:unconfined\n"]
    assert first_child_indent(compact, 1) == 0
    indented_compact = ["  security_opt:\n", "  - seccomp:unconfined\n"]
    assert first_child_indent(indented_compact, 1) == 2
    # A same-indent non-item line is a sibling, not a child.
    assert first_child_indent(["a:\n", "b:\n"], 1) is None


def test_has_merge_key_child() -> None:
    merged = ["web:\n", "  <<: *base\n", "  image: nginx\n"]
    assert has_merge_key_child(merged, 1)
    plain = ["web:\n", "  image: nginx\n"]
    assert not has_merge_key_child(plain, 1)


def test_has_anchor_child() -> None:
    # Anchor carried on the line after the key (anchors the whole mapping).
    anchored = ["web:\n", "    &websvc\n", "    image: nginx\n"]
    assert has_anchor_child(anchored, 1)
    aliased = ["web:\n", "    *base\n"]
    assert has_anchor_child(aliased, 1)
    # Inline `key: &a value` starts with the key, not `&`, so it is not flagged.
    assert not has_anchor_child(["web:\n", "    image: &img nginx\n"], 1)


def test_is_anchored_or_merged() -> None:
    assert is_anchored_or_merged(["web: &a\n", "  image: x\n"], 1)  # inline anchor
    assert is_anchored_or_merged(["web:\n", "  <<: *base\n"], 1)  # merge key
    assert is_anchored_or_merged(
        ["web:\n", "  &websvc\n", "  image: x\n"], 1
    )  # anchor child
    assert not is_anchored_or_merged(["web:\n", "  image: x\n"], 1)  # plain block


def test_block_span_covers_key_and_children() -> None:
    lines = [
        "services:\n",  # 1
        "  web:\n",  # 2
        "    image: nginx\n",  # 3
        "    logging:\n",  # 4
        "      driver: none\n",  # 5
        "  db:\n",  # 6
    ]
    # The web block runs from line 2 through its last child (line 5).
    assert block_span(lines, 2) == (2, 5)
    # The logging sub-block is lines 4-5.
    assert block_span(lines, 4) == (4, 5)


def test_block_span_excludes_trailing_blank_lines() -> None:
    lines = ["web:\n", "  image: x\n", "\n", "db:\n"]
    assert block_span(lines, 1) == (1, 2)


def test_block_span_compact_sequence() -> None:
    # Compact block sequence: items share the key's indent. The span must cover
    # the key and its items, ending at the next sibling key.
    lines = [
        "  web:\n",  # 1
        "    image: nginx\n",  # 2
        "    security_opt:\n",  # 3  (4-space indent)
        "    - seccomp:unconfined\n",  # 4  (compact item at 4-space indent)
        "    - apparmor:unconfined\n",  # 5
        "    environment:\n",  # 6  (sibling key ends the sequence)
    ]
    assert block_span(lines, 3) == (3, 5)


def test_block_span_compact_sequence_with_nested_item() -> None:
    # Long-syntax item under a compact sequence keeps its deeper continuation.
    lines = [
        "    ports:\n",  # 1
        "    - target: 80\n",  # 2  compact item
        "      published: 80\n",  # 3  deeper continuation of the item
        "    other:\n",  # 4  sibling key
    ]
    assert block_span(lines, 1) == (1, 3)


def test_delete_lines_removes_whole_lines() -> None:
    text = "a: 1\nbad: x\nb: 2\n"
    lines = text.splitlines(keepends=True)
    assert apply_edits(text, [delete_lines(lines, 2, 2)]) == "a: 1\nb: 2\n"


def test_delete_lines_spans_multiple_lines() -> None:
    text = "keep: 1\nlogging:\n  driver: none\nkeep2: 2\n"
    lines = text.splitlines(keepends=True)
    assert apply_edits(text, [delete_lines(lines, 2, 3)]) == "keep: 1\nkeep2: 2\n"


def test_delete_lines_final_line_without_trailing_newline() -> None:
    text = "a: 1\nb: 2"  # no trailing newline on the last line
    lines = text.splitlines(keepends=True)
    assert apply_edits(text, [delete_lines(lines, 2, 2)]) == "a: 1\n"


def test_delete_lines_carries_caveat() -> None:
    lines = ["a: 1\n", "b: 2\n"]
    assert delete_lines(lines, 1, 1, caveat="note").caveat == "note"


# --- collect_edits ---------------------------------------------------------


def test_collect_edits_applies_safe_fixers(tmp_path: Path) -> None:
    # A bare service triggers CL-0007 (insert read_only) and CL-0003 (create
    # security_opt); both are first-child insertions at the same point and must
    # both apply, producing valid YAML that re-lints clean for those rules.
    findings, data, lines, text = _findings_for(
        tmp_path,
        "services:\n  web:\n    image: nginx:1.27\n",
    )
    result = collect_edits(findings, data, lines, text)
    fixed_rules = {f.rule_id for f in result.fixed}
    assert {"CL-0003", "CL-0007"} <= fixed_rules
    patched = apply_edits(text, result.edits)
    assert "read_only: true" in patched
    assert "no-new-privileges:true" in patched
    # Idempotent: the targeted rules no longer fire on the patched text, so a
    # second collection produces no further edits.
    re_path = tmp_path / "patched.yml"
    re_path.write_text(patched, encoding="utf-8")
    re_data, re_lines = load_compose(re_path)
    re_findings = run_rules(re_data, re_lines)
    assert {"CL-0003", "CL-0007"}.isdisjoint({f.rule_id for f in re_findings})
    assert collect_edits(re_findings, re_data, re_lines, patched).edits == []


def test_collect_edits_only_filters_by_rule(tmp_path: Path) -> None:
    findings, data, lines, text = _findings_for(
        tmp_path,
        "services:\n  web:\n    image: nginx:1.27\n",
    )
    result = collect_edits(findings, data, lines, text, only={"CL-0007"})
    assert {f.rule_id for f in result.fixed} == {"CL-0007"}
    patched = apply_edits(text, result.edits)
    assert "read_only: true" in patched
    assert "no-new-privileges:true" not in patched


def test_collect_edits_skips_suppressed(tmp_path: Path) -> None:
    findings, data, lines, text = _findings_for(
        tmp_path,
        "services:\n  web:\n    image: nginx:1.27\n",
    )
    # Globally disable CL-0007 so its finding is suppressed, not removed.
    suppressed = run_rules(data, lines, disabled_rules={"CL-0007": "by policy"})
    result = collect_edits(suppressed, data, lines, text)
    assert "CL-0007" not in {f.rule_id for f in result.fixed}


def test_collect_edits_refuses_all_disabled_security_opt(tmp_path: Path) -> None:
    # security_opt's sole entry is seccomp:unconfined (all entries disabled).
    # Auto-fixing this needs the two per-finding fixers to coordinate (remove the
    # disable AND add no-new-privileges) which they can't, so both step aside:
    # CL-0003 declines to append a survivor and CL-0009 declines to empty the
    # block. Both are left manual rather than producing a non-idempotent result.
    findings, data, lines, text = _findings_for(
        tmp_path,
        "services:\n"
        "  web:\n"
        "    image: nginx:1.27\n"
        "    security_opt:\n"
        "      - seccomp:unconfined\n",
    )
    result = collect_edits(findings, data, lines, text, only={"CL-0003", "CL-0009"})
    fixed_rules = {f.rule_id for f in result.fixed}
    manual_rules = {f.rule_id for f in result.manual}
    assert "CL-0003" not in fixed_rules
    assert "CL-0009" not in fixed_rules
    assert {"CL-0003", "CL-0009"} <= manual_rules
    assert result.edits == []


def test_collect_edits_removes_one_item_keeps_others(tmp_path: Path) -> None:
    # Two security_opt entries with the offending one first: CL-0009 removes just
    # that item line (the list survives) and CL-0003 appends after the last item.
    # The edits are on different lines and both apply.
    findings, data, lines, text = _findings_for(
        tmp_path,
        "services:\n"
        "  web:\n"
        "    image: nginx:1.27\n"
        "    security_opt:\n"
        "      - seccomp:unconfined\n"
        "      - label:type:svirt_apache\n",
    )
    result = collect_edits(findings, data, lines, text, only={"CL-0003", "CL-0009"})
    fixed_rules = {f.rule_id for f in result.fixed}
    assert {"CL-0003", "CL-0009"} <= fixed_rules
    patched = apply_edits(text, result.edits)
    assert "seccomp:unconfined" not in patched
    assert "label:type:svirt_apache" in patched
    assert "no-new-privileges:true" in patched


def test_collect_edits_appends_to_compact_security_opt(tmp_path: Path) -> None:
    # Compact block sequence (items at the key's indent): CL-0003 must append a
    # compact item and the result must re-parse and clear CL-0003.
    findings, data, lines, text = _findings_for(
        tmp_path,
        "services:\n"
        "  web:\n"
        "    image: nginx:1.27\n"
        "    security_opt:\n"
        "    - label:type:svirt_apache_t\n",
    )
    result = collect_edits(findings, data, lines, text, only={"CL-0003"})
    assert "CL-0003" in {f.rule_id for f in result.fixed}
    patched = apply_edits(text, result.edits)
    re_path = tmp_path / "patched.yml"
    re_path.write_text(patched, encoding="utf-8")
    re_data, re_lines = load_compose(re_path)
    assert re_data["services"]["web"]["security_opt"] == [
        "label:type:svirt_apache_t",
        "no-new-privileges:true",
    ]


def test_collect_edits_refuses_bare_anchor_service(tmp_path: Path) -> None:
    # A service anchored by a lone `&anchor` first child: inserting a first child
    # before it would re-anchor the wrong node, so the fixers refuse.
    findings, data, lines, text = _findings_for(
        tmp_path,
        "services:\n  web:\n    &websvc\n    image: nginx:1.27\n",
    )
    result = collect_edits(findings, data, lines, text, only={"CL-0003", "CL-0007"})
    assert result.edits == []
    assert {"CL-0003", "CL-0007"} <= {f.rule_id for f in result.manual}


def test_collect_edits_caveats_dedup_and_carry_rule_id(tmp_path: Path) -> None:
    findings, data, lines, text = _findings_for(
        tmp_path,
        "services:\n  web:\n    image: nginx:1.27\n",
    )
    result = collect_edits(findings, data, lines, text, only={"CL-0007"})
    assert any(rule_id == "CL-0007" and caveat for rule_id, caveat in result.caveats)


# --- render_file_diff ------------------------------------------------------


def test_render_file_diff_includes_caveat_banner_and_diff() -> None:
    original = "services:\n  web:\n    image: nginx:1.27\n"
    patched = "services:\n  web:\n    read_only: true\n    image: nginx:1.27\n"
    out = render_file_diff(
        "docker-compose.yml",
        original,
        patched,
        [("CL-0007", "rootfs becomes unwritable")],
    )
    assert "⚠ behavior-changing · CL-0007: rootfs becomes unwritable" in out
    assert "+    read_only: true" in out
    assert "--- docker-compose.yml" in out


def test_render_file_diff_empty_when_unchanged() -> None:
    text = "services:\n  web:\n    image: nginx:1.27\n"
    assert render_file_diff("docker-compose.yml", text, text, []) == ""
