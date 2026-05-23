"""Tests for the fix edit engine (ADR-014)."""

from __future__ import annotations

import pytest

from compose_lint.fix import OverlappingEditError, apply_edits
from compose_lint.models import TextEdit


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
