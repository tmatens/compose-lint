"""Mark the text a finding quotes from the document, and quote references in it.

A rule grades the value a ``.env`` filled in, because that is what deploys, but
a finding must show the ``${NAME}`` and not the value: a CI job often writes
secrets there, and the report is read by whoever opened the pull request.

Replacing the value after the message is built means searching the message for
it, and the search has to be cautious, because the same text is also the rule's
own guidance: a value of ``true`` must not turn ``no-new-privileges:true`` into
``no-new-privileges:${PRIV}``. That caution is where values got through. A
rule quotes a piece of what it parsed, cut wherever its own grammar cuts, and a
search for the whole value or its ``/``-separated parts does not find a piece
cut at ``_``.

So a rule says which part of its message came from the document
(:func:`mark`), and the search inside that part does not need the caution: any
run of :data:`GRAM` characters shared with a value the service used is
replaced. Text outside a mark is the rule's own words and is searched the
cautious way, as before (:mod:`compose_lint.engine`).

The marks are two private-use characters. They never leave a rule:
:class:`compose_lint.rules.BaseRule` strips them from every finding a rule
yields and records where they were (:func:`split`), so a caller of
``rule.check`` sees the message exactly as it will be printed.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

OPEN = ""
CLOSE = ""

# The shortest run of a value replaced inside marked text. The same floor as
# :data:`compose_lint._env_quote.QUOTED_FROM`, for the same reason: a shorter
# value is a configuration token, and the documented limit is that a value
# under 8 characters is shown as written.
GRAM = 8

Span = tuple[int, int]


def mark(text: str) -> str:
    """``text`` marked as quoted from the document.

    A mark character already in ``text`` is written as its visible escape, so
    a value cannot close its own mark and put what follows outside it.
    """
    text = text.replace(OPEN, "\\ue000").replace(CLOSE, "\\ue001")
    return f"{OPEN}{text}{CLOSE}"


_MARKS = re.compile(f"[{OPEN}{CLOSE}]")


def split(text: str) -> tuple[str, tuple[Span, ...]]:
    """``text`` without its marks, and the spans of the result they enclosed."""
    if OPEN not in text and CLOSE not in text:
        return text, ()
    out: list[str] = []
    spans: list[Span] = []
    depth = 0
    start = 0
    length = 0
    last = 0
    for match in _MARKS.finditer(text):
        piece = text[last : match.start()]
        out.append(piece)
        length += len(piece)
        last = match.end()
        if match.group() == OPEN:
            if depth == 0:
                start = length
            depth += 1
        elif depth:
            depth -= 1
            if depth == 0 and length > start:
                spans.append((start, length))
    tail = text[last:]
    out.append(tail)
    length += len(tail)
    if depth and length > start:
        # An unclosed mark covers the rest: more is quoted, never less.
        spans.append((start, length))
    return "".join(out), tuple(spans)


def _fold(text: str) -> str:
    """``text`` lower-cased one character at a time, so offsets are kept."""
    return "".join(low if len(low := ch.lower()) == 1 else ch for ch in text)


def forms(value: str) -> tuple[str, ...]:
    """``value`` and the spellings a message can carry it in.

    A message can hold a value escaped: guidance writes a newline as
    ``\\u000a`` (:func:`compose_lint._output.inline`), a ``repr`` doubles a
    backslash and escapes a quote, and JSON escapes both.
    """
    spellings = {
        value,
        value.replace("\n", "\\u000a"),
        value.replace("\\", "\\\\"),
        value.replace("\\", "\\\\").replace("'", "\\'"),
        value.replace("\\", "\\\\").replace('"', '\\"'),
    }
    return tuple(sorted(spellings, key=len, reverse=True))


def grams(values: Mapping[str, str]) -> dict[str, str]:
    """Every :data:`GRAM`-character run of each value's spellings, to its name."""
    found: dict[str, str] = {}
    for name, value in values.items():
        for form in forms(value):
            folded = _fold(form)
            for index in range(len(folded) - GRAM + 1):
                found.setdefault(folded[index : index + GRAM], name)
    return found


def quote_spans(text: str, spans: Iterable[Span], known: Mapping[str, str]) -> str:
    """``text`` with each run it shares with a value, inside ``spans``, replaced.

    ``known`` is :func:`grams` of the values to look for. A run is replaced by
    the ``${NAME}`` of the value it came from; neighbouring runs of one value
    are one replacement.
    """
    if not known:
        return text
    for start, end in sorted(spans, reverse=True):
        segment = text[start:end]
        quoted = _quote_segment(segment, known)
        if quoted is not segment:
            text = text[:start] + quoted + text[end:]
    return text


def _quote_segment(segment: str, known: Mapping[str, str]) -> str:
    if len(segment) < GRAM:
        return segment
    folded = _fold(segment)
    owner: list[str | None] = [None] * len(segment)
    hit = False
    for index in range(len(folded) - GRAM + 1):
        name = known.get(folded[index : index + GRAM])
        if name is None:
            continue
        hit = True
        for covered in range(index, index + GRAM):
            if owner[covered] is None:
                owner[covered] = name
    if not hit:
        return segment
    out: list[str] = []
    previous: str | None = None
    for ch, name in zip(segment, owner, strict=True):
        if name is None:
            out.append(ch)
        elif name != previous:
            out.append("${" + name + "}")
        previous = name
    return "".join(out)
