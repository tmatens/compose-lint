"""Apply structured text edits produced by rule fixers (see ADR-014).

The fix engine is deliberately a text-patching engine, not a YAML emitter:
edits are spliced into the original file text so comments, key order, and
formatting outside the touched span survive byte-for-byte. ADR-003 rules out a
comment-preserving round-trip parser, so re-serialization is not an option.

All destructive splicing lives in :func:`apply_edits` so the one operation that
rewrites a user's file is in a single, auditable place.
"""

from __future__ import annotations

from compose_lint.models import TextEdit


class OverlappingEditError(ValueError):
    """Raised when two edits target overlapping regions of the same file."""


def _line_starts(text: str) -> list[int]:
    """Return the absolute offset at which each 1-indexed line begins.

    ``starts[0]`` is line 1's offset (always 0). A position on line ``n`` is
    ``starts[n - 1] + (col - 1)``.
    """
    starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            starts.append(index + 1)
    return starts


def _offset(starts: list[int], line: int, col: int) -> int:
    """Convert a 1-indexed ``(line, col)`` position to an absolute offset."""
    return starts[line - 1] + (col - 1)


def apply_edits(text: str, edits: list[TextEdit]) -> str:
    """Splice ``edits`` into ``text`` and return the result.

    Edits are validated to be non-overlapping, then applied from the last
    position to the first so earlier offsets stay valid as later text changes
    length. Adjacent edits (one ending exactly where the next begins) are
    allowed; genuinely overlapping regions raise :class:`OverlappingEditError`.
    An empty ``edits`` list returns ``text`` unchanged.
    """
    if not edits:
        return text

    starts = _line_starts(text)
    spans = [
        (
            _offset(starts, edit.start_line, edit.start_col),
            _offset(starts, edit.end_line, edit.end_col),
            edit,
        )
        for edit in edits
    ]
    spans.sort(key=lambda span: (span[0], span[1]))

    prev_end = -1
    for begin, end, _edit in spans:
        if begin < prev_end:
            raise OverlappingEditError(
                f"edit starting at offset {begin} overlaps a prior edit "
                f"ending at offset {prev_end}"
            )
        prev_end = end

    result = text
    for begin, end, edit in reversed(spans):
        result = result[:begin] + edit.replacement + result[end:]
    return result


# --- Text-shaping helpers shared by rule fixers ---------------------------
#
# These operate on ``source_lines = text.splitlines(keepends=True)``: a
# 1-indexed line ``n`` is ``source_lines[n - 1]``. They exist so individual
# fixers infer indentation, block extent, and refusal conditions the same way
# rather than each re-deriving them (ADR-014, Part 1: "a shared helper layer
# so individual rules stay small").


def line_indent(line: str) -> int:
    """Return the number of leading spaces on ``line`` (newline-insensitive)."""
    body = line.rstrip("\n")
    return len(body) - len(body.lstrip(" "))


def opens_block_body(line: str) -> bool:
    """Return whether ``line`` is a ``key:`` header that opens a block body.

    True when the colon is followed only by whitespace or a comment — meaning
    the value lives in an indented block beneath it. False for an inline value,
    flow collection (``{`` / ``[``), anchor (``&``), or alias (``*``) after the
    colon, and for a line with no colon at all. A fixer that needs to insert
    into or delete a block treats ``False`` as a refusal: there is no plain
    block body to edit unambiguously.
    """
    body = line.rstrip("\n")
    colon = body.find(":")
    if colon == -1:
        return False
    trailing = body[colon + 1 :].strip()
    return not trailing or trailing.startswith("#")


def first_child_indent(source_lines: list[str], key_line: int) -> int | None:
    """Return the indentation of the first child line under ``key_line``.

    Walks forward from the line after ``key_line`` to the first non-blank line.
    Returns its indent if it is deeper than ``key_line`` (a child), otherwise
    ``None`` — meaning the block has no children (the next content is a sibling
    or dedent). Blank lines are skipped; comment lines count as content, mirror-
    ing the original CL-0007 behavior.
    """
    key_indent = line_indent(source_lines[key_line - 1])
    for raw in source_lines[key_line:]:
        if raw.strip() == "":
            continue
        indent = line_indent(raw)
        if indent <= key_indent:
            return None
        return indent
    return None


def has_merge_key_child(source_lines: list[str], key_line: int) -> bool:
    """Return whether the block under ``key_line`` has a merge-key (``<<``) child.

    A merge key means the mapping inherits from a YAML anchor, so an edit's
    correct target (the anchor vs. this block) is ambiguous and the fixer must
    refuse (ADR-014 refusal policy). Only direct children — lines at the first
    child indent — are considered.
    """
    key_indent = line_indent(source_lines[key_line - 1])
    child_indent: int | None = None
    for raw in source_lines[key_line:]:
        if raw.strip() == "":
            continue
        indent = line_indent(raw)
        if indent <= key_indent:
            break
        if child_indent is None:
            child_indent = indent
        if indent == child_indent and raw.strip().startswith("<<"):
            return True
    return False


def is_anchored_or_merged(source_lines: list[str], key_line: int) -> bool:
    """Return whether the block at ``key_line`` is one a fixer must refuse.

    True when the key carries an inline value / flow collection / anchor / alias
    instead of a plain block body, or when the block inherits via a merge key.
    Combines :func:`opens_block_body` and :func:`has_merge_key_child` into the
    single guard deletion and insertion fixers share.
    """
    return not opens_block_body(source_lines[key_line - 1]) or has_merge_key_child(
        source_lines, key_line
    )


def block_span(source_lines: list[str], key_line: int) -> tuple[int, int]:
    """Return the inclusive 1-indexed ``(first, last)`` line span of a block.

    The span covers ``key_line`` and every following line indented deeper than
    it. Blank lines interior to the block are included; a trailing run of blank
    lines after the last child is excluded. Used to delete a block whole.
    """
    key_indent = line_indent(source_lines[key_line - 1])
    last = key_line
    for idx in range(key_line, len(source_lines)):
        if source_lines[idx].strip() == "":
            continue
        if line_indent(source_lines[idx]) <= key_indent:
            break
        last = idx + 1
    return key_line, last


def delete_lines(
    source_lines: list[str],
    first: int,
    last: int,
    *,
    caveat: str | None = None,
) -> TextEdit:
    """Return a :class:`TextEdit` that removes lines ``first``..``last`` whole.

    The region runs from the start of ``first`` to the start of the line after
    ``last`` so the trailing newline goes with the deleted lines. When ``last``
    is the final line of a file with no trailing newline, the region ends at the
    end of that line instead (there is no following line to anchor to).
    """
    if last < len(source_lines):
        return TextEdit(first, 1, last + 1, 1, "", caveat=caveat)
    # `last` is the final line: end at its end (its newline, if any, included).
    end_col = len(source_lines[last - 1]) + 1
    return TextEdit(first, 1, last, end_col, "", caveat=caveat)
