"""Tests for the one authoritative line space (:mod:`compose_lint._lines`).

Regression coverage for the line-space desync: the fix engine's offset table
counted only ``\\n`` while the parser's line numbers came from PyYAML, which
also breaks on lone ``\\r``, U+0085, U+2028 and U+2029. A single such codepoint
inside a quoted scalar shifted every later splice one line, so ``fix --apply``
deleted a line the user never selected and exited 0.

The four trigger characters are covered as a table, not one representative:
patching only the character in the original proof of concept would have left
three live bypasses.
"""

from __future__ import annotations

import pytest
import yaml

from compose_lint._lines import (
    AMBIGUOUS_BREAKS,
    BREAK_CHARS,
    find_ambiguous_break,
    line_starts,
    split_lines,
)
from compose_lint.fix import LineOutOfRangeError, _offset, apply_edits
from compose_lint.models import TextEdit
from compose_lint.parser import ComposeError, loads

# Every codepoint Python or PyYAML treats as a line break, split by whether
# PyYAML accepts a document containing it. `str.splitlines()` breaks on all of
# them; PyYAML rejects the second group with a ReaderError, which is why the
# break set here must be PyYAML's and not `str.splitlines()`'s.
PYYAML_BREAKS = {
    "LF": "\n",
    "CRLF": "\r\n",
    "CR": "\r",
    "NEL": "\x85",
    "LS": "\u2028",
    "PS": "\u2029",
}
# The four PyYAML counts that a naive `\n`-only scan does not: the desync set.
DESYNC_BREAKS = {k: v for k, v in PYYAML_BREAKS.items() if k not in ("LF", "CRLF")}
PYYAML_REJECTS = {
    "VT": "\x0b",
    "FF": "\x0c",
    "FS": "\x1c",
    "GS": "\x1d",
    "RS": "\x1e",
}


def _doc(sep: str) -> str:
    """A valid Compose document with ``sep`` inside a quoted scalar."""
    return (
        "services:\n"
        "  web:\n"
        "    image: nginx:1.25\n"
        "    labels:\n"
        f'      note: "one{sep}two"\n'
        "    read_only: true\n"
    )


def _pyyaml_line(text: str, key: str) -> int:
    """The 1-indexed line PyYAML reports for ``key`` under ``services.web``."""
    node = yaml.compose(text)
    for top_key, top_val in node.value:
        if top_key.value != "services":
            continue
        for _svc_name, svc in top_val.value:
            for child_key, _child_val in svc.value:
                if child_key.value == key:
                    return int(child_key.start_mark.line) + 1
    raise AssertionError(f"{key} not found")


# --- The two functions cannot describe different line spaces ---------------


@pytest.mark.parametrize("name,sep", sorted(PYYAML_BREAKS.items()))
def test_line_starts_agrees_with_split_lines(name: str, sep: str) -> None:
    """``line_starts`` is derived from ``split_lines``, so offsets match lengths."""
    text = _doc(sep)
    lines = split_lines(text)
    starts = line_starts(text)
    assert len(starts) == len(lines) + 1, name
    for index, line in enumerate(lines):
        assert text[starts[index] : starts[index] + len(line)] == line, name
    assert starts[-1] == len(text), name


@pytest.mark.parametrize("name,sep", sorted(PYYAML_BREAKS.items()))
def test_offset_lands_on_the_line_pyyaml_reported(name: str, sep: str) -> None:
    """The core invariant: a PyYAML line number converts to that line's offset."""
    text = _doc(sep)
    line = _pyyaml_line(text, "read_only")
    offset = _offset(line_starts(text), line, 1)
    assert text[offset:].startswith("    read_only: true"), name


@pytest.mark.parametrize("name,sep", sorted(PYYAML_BREAKS.items()))
def test_split_lines_indexes_as_pyyaml_numbers(name: str, sep: str) -> None:
    """``source_lines[n - 1]`` is the line PyYAML called ``n``."""
    text = _doc(sep)
    line = _pyyaml_line(text, "read_only")
    assert split_lines(text)[line - 1].strip() == "read_only: true", name


def test_crlf_is_one_break_not_two() -> None:
    assert split_lines("a\r\nb\r\n") == ["a\r\n", "b\r\n"]


def test_trailing_break_does_not_make_an_empty_final_line() -> None:
    assert split_lines("a\nb\n") == ["a\n", "b\n"]
    assert split_lines("a\nb") == ["a\n", "b"]


def test_empty_text() -> None:
    assert split_lines("") == []
    assert line_starts("") == [0]


def test_break_chars_is_exactly_pyyamls_set() -> None:
    """Pin the break set: `str.splitlines()`'s extra characters are excluded."""
    assert set(BREAK_CHARS) == {"\n", "\r", "\x85", "\u2028", "\u2029"}
    for char in PYYAML_REJECTS.values():
        assert char not in BREAK_CHARS


@pytest.mark.parametrize("name,char", sorted(PYYAML_REJECTS.items()))
def test_pyyaml_rejects_the_characters_we_exclude(name: str, char: str) -> None:
    """The excluded characters are unreachable: PyYAML refuses such documents.

    This is the evidence that excluding them cannot hide a real document from
    the fixers — it is not a judgement call.
    """
    with pytest.raises(yaml.YAMLError):
        yaml.compose(_doc(char))


# --- Bounds checking replaces a bare IndexError ----------------------------


def test_offset_rejects_a_line_past_the_end() -> None:
    starts = line_starts("a\nb\n")
    with pytest.raises(LineOutOfRangeError, match="outside the file"):
        _offset(starts, 99, 1)


def test_offset_rejects_a_nonpositive_line() -> None:
    starts = line_starts("a\nb\n")
    with pytest.raises(LineOutOfRangeError, match="outside the file"):
        _offset(starts, 0, 1)


def test_offset_rejects_a_nonpositive_column() -> None:
    starts = line_starts("a\nb\n")
    with pytest.raises(LineOutOfRangeError, match="below 1"):
        _offset(starts, 1, 0)


def test_offset_allows_the_end_of_file_sentinel() -> None:
    """Appending at EOF addresses the line after the last one (CL-0003 relies on it)."""
    text = "a: 1\nb: 2\n"
    starts = line_starts(text)
    assert _offset(starts, 3, 1) == len(text)
    assert apply_edits(text, [TextEdit(3, 1, 3, 1, "c: 3\n")]) == "a: 1\nb: 2\nc: 3\n"


def test_apply_edits_raises_the_domain_error_not_indexerror() -> None:
    with pytest.raises(LineOutOfRangeError):
        apply_edits("a: 1\n", [TextEdit(9, 1, 9, 1, "x")])


# --- Splicing is correct in every break space ------------------------------


@pytest.mark.parametrize("name,sep", sorted(DESYNC_BREAKS.items()))
def test_edit_splices_at_the_pyyaml_line_for_every_break(name: str, sep: str) -> None:
    """Deleting "the line PyYAML calls N" removes exactly that line."""
    text = _doc(sep)
    line = _pyyaml_line(text, "read_only")
    lines = split_lines(text)
    end_col = len(lines[line - 1]) + 1
    patched = apply_edits(text, [TextEdit(line, 1, line, end_col, "")])
    assert "read_only" not in patched, name
    # ...and nothing else was touched.
    assert 'note: "one' in patched, name
    assert "image: nginx:1.25" in patched, name


# --- Ambiguous breaks are refused at the parser boundary -------------------


def test_find_ambiguous_break_ignores_lf_and_crlf() -> None:
    assert find_ambiguous_break("a\nb\n") is None
    assert find_ambiguous_break("a\r\nb\r\n") is None
    assert find_ambiguous_break("") is None


@pytest.mark.parametrize("name,sep", sorted(DESYNC_BREAKS.items()))
def test_find_ambiguous_break_reports_line_and_character(name: str, sep: str) -> None:
    found = find_ambiguous_break(f"a\nb\nc{sep}d")
    assert found is not None, name
    line, description = found
    assert line == 3, name
    assert description in AMBIGUOUS_BREAKS.values(), name


def test_find_ambiguous_break_counts_preceding_crlf_lines() -> None:
    """The reported line number is in the same space as everything else."""
    found = find_ambiguous_break("a\r\nb\r\nc\x85d")
    assert found == (3, AMBIGUOUS_BREAKS["\x85"])


@pytest.mark.parametrize("name,sep", sorted(DESYNC_BREAKS.items()))
def test_loads_refuses_a_document_with_an_ambiguous_break(name: str, sep: str) -> None:
    source = f'services:\n  web:\n    image: nginx\n    labels:\n      n: "a{sep}b"\n'
    with pytest.raises(ComposeError, match="Ambiguous line break"):
        loads(source)


def test_loads_accepts_lf_and_crlf_identically() -> None:
    """The read-shape change must not move a single line number."""
    source = "services:\n  web:\n    image: nginx\n    privileged: true\n"
    lf_data, lf_lines = loads(source)
    crlf_data, crlf_lines = loads(source.replace("\n", "\r\n"))
    assert lf_data == crlf_data
    assert lf_lines == crlf_lines
