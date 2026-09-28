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

import contextlib
import os
import re
import sys
from typing import TextIO

# Code-point ranges (inclusive) that can spoof or corrupt terminal output:
# C0/C1 controls — ANSI/escape-sequence injection, including the ESC and CSI
# introducers — plus DEL, and the bidirectional and zero-width formatting
# characters that visually reorder or hide text (e.g. U+202E RIGHT-TO-LEFT
# OVERRIDE rendering a malicious tag as a benign one). The bidi entries are
# Unicode's whole `Bidi_Control` set; the invisible ones are the
# `Default_Ignorable_Code_Point`s that render as nothing at all in a terminal.
# Hand-maintained rather than derived from `unicodedata`, which exposes neither
# property. Built from hex so no
# invisible literals live in source. Tab and newline are excluded here and
# handled by the two functions below, which differ only in whether a newline is
# structural at that sink.
_UNSAFE_RANGES = (
    (0x00, 0x08),
    (0x0B, 0x1F),
    (0x7F, 0x9F),
    (0xAD, 0xAD),  # SOFT HYPHEN
    (0x061C, 0x061C),  # ARABIC LETTER MARK (Bidi_Control)
    (0x180E, 0x180E),  # MONGOLIAN VOWEL SEPARATOR
    (0x200B, 0x200F),
    # LINE and PARAGRAPH SEPARATOR: a line break to `str.splitlines()` and to
    # some renderers, so text after one can look like, or be read as, a line of
    # its own.
    (0x2028, 0x2029),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),  # interlinear annotation controls
    (0xE0000, 0xE007F),  # tag characters
)


def _pattern(*extra: str) -> re.Pattern[str]:
    ranges = "".join(f"{chr(lo)}-{chr(hi)}" for lo, hi in _UNSAFE_RANGES)
    return re.compile("[" + ranges + "".join(extra) + "]")


_UNSAFE_OUTPUT_CHARS = _pattern()
_UNSAFE_LINE_CHARS = _pattern("\n")


def _escape(match: re.Match[str]) -> str:
    code = ord(match.group())
    # Past the BMP a four-digit `\u` would read as a shorter code point
    # followed by a digit, so those take Python's eight-digit form.
    return f"\\U{code:08x}" if code > 0xFFFF else f"\\u{code:04x}"


# CI log parsers treat some printable text as commands. GitHub Actions and
# Azure Pipelines run `##[command]` found anywhere in a line, Azure runs
# `##vso[command]` anywhere in a line too, and GitHub also runs `::command::`
# at the start of a line. A Compose file's own strings are printed in the
# report, so each opening is broken with the same visible escape the control
# characters get.
#
# "The start of a line" is after the runner's `TrimStart()`, which strips every
# character .NET calls white space, not only space and tab: U+00A0, U+2000 to
# U+200A, U+3000 and the rest of Unicode's space separators, plus U+0085 and
# the line and paragraph separators. A no-break space before `::` got past a
# `[ \t]*` prefix and was acted on. Python's `\s` covers that whole set (and
# the four information separators besides), so the prefix is any white space
# but the newline that ends the line.
_LEGACY_COMMAND = re.compile(r"##(vso)?\[", re.IGNORECASE)
_LINE_COMMAND = re.compile(r"^([^\S\n]*):(?=:)", re.MULTILINE)


def _defuse_commands(text: str) -> str:
    text = _LEGACY_COMMAND.sub(lambda m: "##" + (m.group(1) or "") + "\\u005b", text)
    return _LINE_COMMAND.sub("\\1\\\\u003a", text)


def defuse_json(document: str) -> str:
    """Break every CI command opener inside serialized JSON, keeping it valid.

    JSON and SARIF go to stdout, which a bare CLI run prints to the job log, and
    ``json.dumps`` leaves ``##[`` in a string as it is. The bracket is written
    as the JSON escape ``\\u005b`` instead, which decodes to the same string, so
    a consumer sees identical data. A ``#`` only ever appears inside a string,
    so no structural bracket is touched. A line-leading ``::`` cannot occur: a
    string carries its newlines escaped, and every line starts with
    indentation followed by structure.
    """
    return _LEGACY_COMMAND.sub(
        lambda m: "##" + (m.group(1) or "") + "\\u005b", document
    )


def sanitize(text: str) -> str:
    """Render terminal-unsafe code points as visible ``\\uXXXX`` escapes.

    Newlines and tabs survive, so multi-line content (fix guidance, a unified
    diff) keeps its layout. Clean text is returned unchanged. CI workflow
    command openers (``##[``, ``##vso[`` and a line-leading ``::``) are
    escaped too.
    """
    return _defuse_commands(_UNSAFE_OUTPUT_CHARS.sub(_escape, text))


def sanitize_line(text: str) -> str:
    """:func:`sanitize`, and escape newlines too.

    For a value rendered as one record in a newline-delimited report. Passing a
    newline through there is not a layout question: the text after it starts at
    column zero and is indistinguishable from a line compose-lint wrote itself,
    which is how a service name could forge a finding against another file or a
    ``✓ PASS`` verdict.
    """
    return _defuse_commands(_UNSAFE_LINE_CHARS.sub(_escape, text))


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
    _write_diagnostic("\n".join(lines) + "\n", stream)


def emit_block(text: str) -> None:
    """Write pre-formatted multi-line text (a diff, a banner) to stderr.

    Line structure is preserved because it is the message; everything that
    could redraw the terminal is escaped.
    """
    _write_diagnostic(sanitize(text), None)


def _write_diagnostic(text: str, stream: TextIO | None) -> None:
    """Write to stderr if it can be written, and otherwise drop the text.

    Stdout carries the report and stderr only narrates it, so losing stderr
    must not cost the report. Two ways it did:

    * Started with fd 2 closed, CPython sets ``sys.stderr`` to ``None``, and
      ``print(file=None)`` means *stdout* — every note landed after the closing
      brace of the JSON or SARIF document on stdout.
    * A stderr that fails on write (a full disk, a reader that went away)
      raised out of the first note, before the report was printed, and exited
      120: outside ADR-006's codes, with nothing on stdout.

    The flush is inside the guard because a buffered failure otherwise
    surfaces at interpreter shutdown, where it becomes that same exit 120.
    """
    target = stream if stream is not None else sys.stderr
    if target is None:
        return
    try:
        target.write(text)
        target.flush()
    except (OSError, ValueError):
        _discard_stderr(target)


def _discard_stderr(target: TextIO) -> None:
    """Point a failed stderr at the null device so no later write can fail.

    The same move as ``cli._discard_stdout``: the interpreter flushes stderr
    once more at exit, outside any handler, so the descriptor itself has to
    stop failing for the chosen exit code to stand.
    """
    with (
        contextlib.suppress(AttributeError, OSError, ValueError),
        open(os.devnull, "wb") as null,
    ):
        os.dup2(null.fileno(), target.fileno())
