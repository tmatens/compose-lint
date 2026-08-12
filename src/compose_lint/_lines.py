"""The single authoritative definition of "a line" for compose-lint.

Every line number compose-lint handles originates with PyYAML: the parser's
``lines`` map is built from ``start_mark.line``, fixers index ``source_lines``
with those numbers, and the fix engine converts them to byte offsets to splice
edits. Three different splitters used to serve those three roles, and they did
not agree — ``fix._line_starts`` counted only ``\\n`` while PyYAML and
``str.splitlines()`` also break on lone ``\\r``, U+0085, U+2028 and U+2029. One
such codepoint inside a quoted scalar shifted every later splice one line, so
``fix --apply`` deleted a line the user never selected.

This module removes the possibility of disagreement rather than patching the
one splitter that was wrong: :func:`split_lines` and :func:`line_starts` are
derived from *the same* scan, so an offset table can never describe a different
line space than the list of lines it indexes.

The break set is **PyYAML's**, not ``str.splitlines()``'s. That is the correct
authority because the line numbers being converted were authored by PyYAML.
``str.splitlines()`` additionally breaks on ``\\v``, ``\\f``, ``\\x1c``,
``\\x1d`` and ``\\x1e``; PyYAML rejects documents containing those with a
``ReaderError``, so on any document that parses the two agree — but matching
PyYAML keeps that agreement a property of the code rather than a coincidence of
the reader's rejection list.
"""

from __future__ import annotations

# The characters PyYAML's Reader counts as advancing a line (see its
# ``Reader.forward`` / ``Scanner.scan_line_break``). ``\r\n`` counts once.
BREAK_CHARS = "\n\r\x85\u2028\u2029"
_BREAKS = frozenset(BREAK_CHARS)


def split_lines(text: str) -> list[str]:
    """Split ``text`` into lines, keeping each line's terminator attached.

    Equivalent in shape to ``text.splitlines(keepends=True)`` but using
    PyYAML's break set, so ``source_lines[n - 1]`` is the line PyYAML called
    ``n``. A trailing break does not produce a final empty line.
    """
    lines: list[str] = []
    start = 0
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char in _BREAKS:
            # CRLF is one break, so the LF is consumed with the CR rather than
            # starting an empty line of its own.
            if char == "\r" and index + 1 < length and text[index + 1] == "\n":
                index += 2
            else:
                index += 1
            lines.append(text[start:index])
            start = index
        else:
            index += 1
    if start < length:
        lines.append(text[start:])
    return lines


def line_starts(text: str) -> list[int]:
    """Return the absolute offset at which each 1-indexed line begins.

    ``starts[0]`` is line 1's offset (always 0); a position on line ``n`` is
    ``starts[n - 1] + (col - 1)``. Derived by accumulating :func:`split_lines`
    lengths, so the two functions cannot describe different line spaces.

    The list carries one entry per line plus a final sentinel at ``len(text)``.
    The sentinel makes "the start of the line after the last one" addressable,
    which fixers rely on when appending at the end of a file (see
    ``CL0003._append_item``).
    """
    starts = [0]
    offset = 0
    for line in split_lines(text):
        offset += len(line)
        starts.append(offset)
    return starts


# Breaks PyYAML honors that a consumer splitting on ``\n`` does not see. A
# document containing one has no line numbering both sides agree on: the number
# compose-lint reports (PyYAML's, the only correct one for a YAML construct)
# names a different line in the editor, the SARIF viewer, and the CI annotation.
AMBIGUOUS_BREAKS = {
    "\r": "U+000D CARRIAGE RETURN outside a CRLF pair",
    "\x85": "U+0085 NEXT LINE",
    "\u2028": "U+2028 LINE SEPARATOR",
    "\u2029": "U+2029 PARAGRAPH SEPARATOR",
}


def find_ambiguous_break(text: str) -> tuple[int, str] | None:
    """Return ``(line, description)`` of the first ambiguous break, else ``None``.

    ``line`` is 1-indexed in :func:`split_lines`' space. ``\\n`` and ``\\r\\n``
    are unambiguous and skipped; a ``\\r`` *not* followed by ``\\n`` is not.
    """
    line = 1
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\r":
            if index + 1 < length and text[index + 1] == "\n":
                index += 2
                line += 1
                continue
            return line, AMBIGUOUS_BREAKS["\r"]
        if char == "\n":
            line += 1
            index += 1
            continue
        if char in AMBIGUOUS_BREAKS:
            return line, AMBIGUOUS_BREAKS[char]
        index += 1
    return None
