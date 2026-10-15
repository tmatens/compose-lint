"""Render a rule doc's markdown for a terminal reader.

``--explain`` shows ``docs/rules/CL-XXXX.md``, the same file the docs site
builds from. Printed raw, a terminal reader gets ``**`` around every label,
backticks around every path, ``[text](../severity.md)`` links that lead
nowhere, table pipes, and paragraphs written one sentence per source line at
whatever length the author typed. This turns that into text: markers become
bold, italic or color (or nothing, without color), links keep their text and
show a web address dimmed after it, tables line up or become one record per
row, and paragraphs and list items re-wrap to the terminal.

Only a terminal gets this. Piped output stays the raw markdown, byte for byte
(ADR-034), so a script or a ``> CL-0001.md`` still receives the file.

It covers the markdown the rule docs use and nothing more — headings, lists,
fenced code, pipe tables, and inline code, bold, italic and links — because
pulling in a markdown library would add a runtime dependency for a help page.
``tests/test_terminal_markdown.py`` renders every shipped doc and fails on any
marker left behind, so a doc that reaches for new syntax is caught.
"""

from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass

_BOLD = "\033[1m"
_ITALIC = "\033[3m"
_CODE = "\033[36m"
_DIM = "\033[2m"
_RESET = "\033[0m"

_ANSI = re.compile(r"\033\[[0-9;]*m")
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_FENCE = re.compile(r"^\s*```")
_LIST_ITEM = re.compile(r"^(\s*)([-*]|\d+\.)\s+(.*)$")
_TABLE_RULE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$")

# One inline token per match, earliest first. Code spans come first so their
# contents are never read as markup; a link's text is rendered recursively.
_INLINE = re.compile(
    r"(?P<code>`+)(?P<code_body>.+?)(?P=code)"
    r"|\[(?P<link_text>[^\]]+)\]\((?P<link_url>[^)\s]+)\)"
    r"|\*\*(?P<bold>.+?)\*\*"
    r"|(?<![\w*])\*(?P<italic>[^*\s](?:[^*]*[^*\s])?)\*(?![\w*])"
)


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    style: str


def _inline(text: str, color: bool = True) -> tuple[str, list[_Span]]:
    """Strip inline markup from ``text``; return the plain text and its styles.

    Without color a code span keeps its backticks: they are the only thing
    marking ``reason:`` as a key rather than the end of a sentence.
    """
    out: list[str] = []
    spans: list[_Span] = []
    length = 0

    def add(plain: str, style: str | None = None) -> None:
        nonlocal length
        if style is not None and plain:
            spans.append(_Span(length, length + len(plain), style))
        out.append(plain)
        length += len(plain)

    pos = 0
    for match in _INLINE.finditer(text):
        add(text[pos : match.start()])
        if match.group("code") is not None:
            body = match.group("code_body").strip()
            add(body if color else f"`{body}`", _CODE)
        elif match.group("link_text") is not None:
            inner, inner_spans = _inline(match.group("link_text"), color)
            spans.extend(
                _Span(s.start + length, s.end + length, s.style) for s in inner_spans
            )
            add(inner)
            url = match.group("link_url")
            if url.startswith(("http://", "https://")) and url != inner:
                add(" ")
                add(f"({url})", _DIM)
        elif match.group("bold") is not None:
            inner, inner_spans = _inline(match.group("bold"), color)
            spans.extend(
                _Span(s.start + length, s.end + length, s.style) for s in inner_spans
            )
            add(inner, _BOLD)
        else:
            inner, inner_spans = _inline(match.group("italic"), color)
            spans.extend(
                _Span(s.start + length, s.end + length, s.style) for s in inner_spans
            )
            add(inner, _ITALIC)
        pos = match.end()
    add(text[pos:])
    return "".join(out), spans


def _paint(plain: str, spans: list[_Span], start: int, color: bool) -> str:
    """Apply ``spans`` (offsets into the full text) to the slice at ``start``."""
    if not color or not spans:
        return plain
    end = start + len(plain)
    styles = [""] * len(plain)
    for span in spans:
        for i in range(max(span.start, start), min(span.end, end)):
            styles[i - start] += span.style
    pieces: list[str] = []
    current = ""
    for ch, style in zip(plain, styles, strict=True):
        if style != current:
            pieces.append(_RESET if current else "")
            pieces.append(style)
            current = style
        pieces.append(ch)
    if current:
        pieces.append(_RESET)
    return "".join(pieces)


def _wrap(
    text: str,
    width: int,
    color: bool,
    *,
    first: str = "",
    rest: str = "",
    base_style: str = "",
) -> list[str]:
    """Render inline markup in ``text`` and wrap it, keeping styles across breaks."""
    plain, spans = _inline(text, color)
    if base_style:
        spans.insert(0, _Span(0, len(plain), base_style))
    # Indents are wrapped as plain spaces of the prefix's visible width, so a
    # styled prefix (a bold table label) does not count its escape codes.
    first_width = len(_ANSI.sub("", first))
    lines = textwrap.wrap(
        plain,
        width=max(width, first_width + 20),
        initial_indent=" " * first_width,
        subsequent_indent=" " * len(rest),
        break_long_words=False,
        break_on_hyphens=False,
    )
    rendered: list[str] = []
    pos = 0
    for index, wrapped in enumerate(lines):
        line = wrapped[first_width if index == 0 else len(rest) :]
        start = plain.find(line, pos)
        if start < 0:  # pragma: no cover - textwrap only removes whitespace
            start = pos
        pos = start + len(line)
        prefix = first if index == 0 else rest
        rendered.append(prefix + _paint(line, spans, start, color))
    return rendered or [first.rstrip()]


def _split_row(line: str) -> list[str]:
    """Split a pipe-table row into cells, leaving pipes inside code spans alone."""
    cells: list[str] = []
    cell: list[str] = []
    in_code = False
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body) and body[i + 1] == "|":
            cell.append("|")
            i += 2
            continue
        if ch == "`":
            in_code = not in_code
        if ch == "|" and not in_code:
            cells.append("".join(cell).strip())
            cell = []
        else:
            cell.append(ch)
        i += 1
    cells.append("".join(cell).strip())
    return cells


def _table(rows: list[str], width: int, color: bool) -> list[str]:
    """Line a table up when it fits; otherwise print one record per row."""
    header = _split_row(rows[0])
    body = [_split_row(r) for r in rows[1:] if not _TABLE_RULE.match(r)]
    plain_header = [_inline(c, color)[0] for c in header]
    plain_body = [[_inline(c, color)[0] for c in row] for row in body]
    columns = len(header)
    widths = [len(h) for h in plain_header]
    for row in plain_body:
        for i, cell in enumerate(row[:columns]):
            widths[i] = max(widths[i], len(cell))
    gap = "  "
    if sum(widths) + len(gap) * (columns - 1) <= width:

        def render_row(cells: list[str], style: str = "") -> str:
            parts = []
            for i in range(columns):
                raw = cells[i] if i < len(cells) else ""
                plain, spans = _inline(raw, color)
                if style:
                    spans.insert(0, _Span(0, len(plain), style))
                parts.append(
                    _paint(plain, spans, 0, color) + " " * (widths[i] - len(plain))
                )
            return gap.join(parts).rstrip()

        rule = gap.join("─" * w for w in widths)
        return [
            render_row(header, _BOLD),
            _paint(rule, [_Span(0, len(rule), _DIM)], 0, color),
            *(render_row(row) for row in body),
        ]

    out: list[str] = []
    for row in body:
        if out:
            out.append("")
        for i, cell in enumerate(row[:columns]):
            label = plain_header[i]
            label_text = _paint(
                label + ":", [_Span(0, len(label) + 1, _BOLD)], 0, color
            )
            out.extend(_wrap(cell, width, color, first=f"{label_text} ", rest="  "))
    return out


def render(markdown: str, *, width: int, color: bool) -> str:
    """Return ``markdown`` as wrapped, styled terminal text."""
    # A markdown file, not a Compose document: `_lines.split_lines`'s YAML
    # break set is not the authority here, plain newlines are.
    lines = [line.rstrip("\r") for line in markdown.split("\n")]
    out: list[str] = []
    i = 0

    def blank() -> None:
        if out and out[-1] != "":
            out.append("")

    while i < len(lines):
        line = lines[i]
        if not line.strip():
            blank()
            i += 1
            continue

        if _FENCE.match(line):
            fence_indent = len(line) - len(line.lstrip())
            i += 1
            while i < len(lines) and not _FENCE.match(lines[i]):
                code = (
                    lines[i][fence_indent:]
                    if lines[i][:fence_indent].isspace()
                    else lines[i]
                )
                out.append("    " + code.rstrip())
                i += 1
            i += 1
            continue

        heading = _HEADING.match(line)
        if heading:
            blank()
            out.extend(_wrap(heading.group(2), width, color, base_style=_BOLD))
            out.append("")
            i += 1
            continue

        if line.lstrip().startswith("|"):
            rows = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                rows.append(lines[i])
                i += 1
            out.extend(_table(rows, width, color))
            continue

        item = _LIST_ITEM.match(line)
        if item:
            indent, marker, text = item.groups()
            parts = [text]
            i += 1
            while (
                i < len(lines)
                and lines[i].strip()
                and not _LIST_ITEM.match(lines[i])
                and not _HEADING.match(lines[i])
                and not _FENCE.match(lines[i])
                and not lines[i].lstrip().startswith("|")
            ):
                parts.append(lines[i].strip())
                i += 1
            bullet = "•" if marker in ("-", "*") else marker
            first = f"{indent}{bullet} "
            out.extend(
                _wrap(" ".join(parts), width, color, first=first, rest=" " * len(first))
            )
            continue

        indent = line[: len(line) - len(line.lstrip())]
        parts = [line.strip()]
        i += 1
        while (
            i < len(lines)
            and lines[i].strip()
            and not _LIST_ITEM.match(lines[i])
            and not _HEADING.match(lines[i])
            and not _FENCE.match(lines[i])
            and not lines[i].lstrip().startswith("|")
        ):
            parts.append(lines[i].strip())
            i += 1
        out.extend(_wrap(" ".join(parts), width, color, first=indent, rest=indent))

    while out and out[-1] == "":
        out.pop()
    return "\n".join(out)
