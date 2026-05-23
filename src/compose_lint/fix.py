"""Apply structured text edits produced by rule fixers (see ADR-014).

The fix engine is deliberately a text-patching engine, not a YAML emitter:
edits are spliced into the original file text so comments, key order, and
formatting outside the touched span survive byte-for-byte. ADR-003 rules out a
comment-preserving round-trip parser, so re-serialization is not an option.

All destructive splicing lives in :func:`apply_edits` so the one operation that
rewrites a user's file is in a single, auditable place.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
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
