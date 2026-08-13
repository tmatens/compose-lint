"""The one place externally-derived text is prepared for a terminal.

Everything compose-lint prints about a Compose file is attacker-authored to
some degree: service names, image references, env keys, parse-error text that
quotes the document, and source excerpts read straight off disk. A terminal or
CI log renders control sequences, so printing any of it verbatim lets the file
being linted write the report about itself — erase findings already on screen,
forge a verdict line, or reorder text with a bidi override so the diff a human
approves is not the diff that will be applied.

Sanitizing was previously a private helper inside the text formatter, so it
protected the formatter's own fields and nothing else: 26 other print sites
emitted attacker-derived text raw. Keeping the escaping here, and routing every
stderr write through :func:`emit`, makes it the default rather than something
each new call site has to remember.

Two levels, because the sinks differ:

* :func:`sanitize` keeps ``\\n`` and ``\\t`` — for content that is legitimately
  multi-line, such as a rule's fix guidance or a unified diff.
* :func:`sanitize_line` also escapes ``\\n`` — for anything rendered as one
  record in a newline-delimited report, where an embedded newline lets the
  value occupy the report's own left margin and forge a line.
"""

from __future__ import annotations

import re
import sys
from typing import TextIO

# Code-point ranges (inclusive) that can spoof or corrupt terminal output:
# C0/C1 controls — ANSI/escape-sequence injection, including the ESC and CSI
# introducers — plus DEL, and the bidirectional and zero-width formatting
# characters that visually reorder or hide text (e.g. U+202E RIGHT-TO-LEFT
# OVERRIDE rendering a malicious tag as a benign one). Built from hex so no
# invisible literals live in source. Tab and newline are excluded here and
# handled by the two functions below, which differ only in whether a newline is
# structural at that sink.
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


def _pattern(*extra: str) -> re.Pattern[str]:
    ranges = "".join(f"{chr(lo)}-{chr(hi)}" for lo, hi in _UNSAFE_RANGES)
    return re.compile("[" + ranges + "".join(extra) + "]")


_UNSAFE_OUTPUT_CHARS = _pattern()
_UNSAFE_LINE_CHARS = _pattern("\n")


def _escape(match: re.Match[str]) -> str:
    return f"\\u{ord(match.group()):04x}"


def sanitize(text: str) -> str:
    """Render terminal-unsafe code points as visible ``\\uXXXX`` escapes.

    Newlines and tabs survive, so multi-line content (fix guidance, a unified
    diff) keeps its layout. Clean text is returned unchanged.
    """
    return _UNSAFE_OUTPUT_CHARS.sub(_escape, text)


def sanitize_line(text: str) -> str:
    """:func:`sanitize`, and escape newlines too.

    For a value rendered as one record in a newline-delimited report. Passing a
    newline through there is not a layout question: the text after it starts at
    column zero and is indistinguishable from a line compose-lint wrote itself,
    which is how a service name could forge a finding against another file or a
    ``✓ PASS`` verdict.
    """
    return _UNSAFE_LINE_CHARS.sub(_escape, text)


# Continuation lines are indented so nothing after an embedded newline can sit
# in the report's own left margin.
_CONTINUATION_INDENT = "  "


def emit(message: str, *, stream: TextIO | None = None) -> None:
    """Write a sanitized diagnostic to stderr, indenting any continuation.

    Every human-facing status and error line goes through here. Sanitizing at
    the call site is opt-in and was therefore skipped 26 times; sanitizing at
    the sink is not.

    Newlines are kept rather than escaped, because some diagnostics are
    legitimately multi-line and lose their meaning without them — PyYAML's
    parse errors carry the offending source line and a caret under the column.
    Escaping those into ``\u000a`` produced one unreadable line and threw away
    the most useful part of the message.

    What the forgery actually needs is the report's left margin, so that is
    what is denied: every line after the first is indented. An embedded newline
    still shows the text that followed it, but visibly as a continuation of
    this record rather than as a line compose-lint wrote itself.
    """
    body = sanitize(message)
    first, *rest = body.split("\n")
    lines = [first] + [_CONTINUATION_INDENT + line for line in rest]
    print("\n".join(lines), file=stream if stream is not None else sys.stderr)


def emit_block(text: str) -> None:
    """Write pre-formatted multi-line text (a diff, a banner) to stderr.

    Line structure is preserved because it is the message; everything that
    could redraw the terminal is escaped.
    """
    print(sanitize(text), end="", file=sys.stderr)
