"""Apply structured text edits produced by rule fixers (see ADR-014).

The fix engine is deliberately a text-patching engine, not a YAML emitter:
edits are spliced into the original file text so comments, key order, and
formatting outside the touched span survive byte-for-byte. ADR-003 rules out a
comment-preserving round-trip parser, so re-serialization is not an option.

All destructive splicing lives in :func:`apply_edits` so the one operation that
rewrites a user's file is in a single, auditable place. :func:`collect_edits`
gathers the edits across all findings for a file, refusing any that conflict,
and :func:`render_file_diff` turns the result into the dry-run unified diff.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, TextEdit

if TYPE_CHECKING:
    from collections.abc import Iterable


# security_opt directives that disable a default platform profile — CL-0009's
# territory. Shared here so CL-0003 can decline to append into a block whose
# entries are *all* profile-disables: CL-0009 will act on those, and appending a
# survivor first would let a second `fix` pass delete them (breaking idempotency,
# ADR-014). Values are matched against `str(opt).strip().lower()`.
DISABLED_SECURITY_PROFILES = frozenset(
    {"seccomp:unconfined", "apparmor:unconfined", "label:disable"}
)


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


def _is_seq_item(line: str) -> bool:
    """Return whether ``line`` is a block-sequence entry (``-`` or ``- ...``)."""
    stripped = line.lstrip()
    return stripped == "-" or stripped.startswith("- ")


def first_child_indent(source_lines: list[str], key_line: int) -> int | None:
    """Return the indentation of the first child line under ``key_line``.

    Walks forward from the line after ``key_line`` to the first non-blank line.
    Returns its indent if it is a child, otherwise ``None`` — meaning the block
    has no children (the next content is a sibling or dedent). A line is a child
    when it is indented deeper than ``key_line`` *or* it sits at ``key_line``'s
    own indent and is a block-sequence item (``- ...``): YAML lets a sequence
    value share its key's indentation (the "compact" style), and those items are
    still children of the key. Blank lines are skipped; comment lines count as
    content, mirroring the original CL-0007 behavior.
    """
    key_indent = line_indent(source_lines[key_line - 1])
    for raw in source_lines[key_line:]:
        if raw.strip() == "":
            continue
        indent = line_indent(raw)
        if indent > key_indent:
            return indent
        if indent == key_indent and _is_seq_item(raw):
            return indent
        return None
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


def has_anchor_child(source_lines: list[str], key_line: int) -> bool:
    """Return whether the block under ``key_line`` has a bare anchor/alias child.

    A mapping can carry its anchor on the line *after* the key (``svc:`` then a
    lone ``&svc`` as the first child) rather than inline. That anchors the whole
    mapping, so inserting a new first child before it would re-anchor the wrong
    node and break the file — the fixer must refuse (ADR-014). Detects a direct
    child line that is a lone anchor (``&name``) or alias (``*name``); inline
    forms like ``key: &a value`` start with the key, not ``&``/``*``, and are
    not flagged. Only direct children (lines at the first child indent) count.
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
        if indent == child_indent:
            stripped = raw.strip()
            if stripped.startswith("&") or stripped.startswith("*"):
                return True
    return False


def is_anchored_or_merged(source_lines: list[str], key_line: int) -> bool:
    """Return whether the block at ``key_line`` is one a fixer must refuse.

    True when the key carries an inline value / flow collection / anchor / alias
    instead of a plain block body, when the block inherits via a merge key, or
    when it is anchored by a lone ``&anchor`` child line. Combines
    :func:`opens_block_body`, :func:`has_merge_key_child`, and
    :func:`has_anchor_child` into the single guard deletion and insertion fixers
    share.
    """
    return (
        not opens_block_body(source_lines[key_line - 1])
        or has_merge_key_child(source_lines, key_line)
        or has_anchor_child(source_lines, key_line)
    )


def block_span(source_lines: list[str], key_line: int) -> tuple[int, int]:
    """Return the inclusive 1-indexed ``(first, last)`` line span of a block.

    The span covers ``key_line`` and every following child line. Lines indented
    deeper than ``key_line`` are children. When the block is a *compact*
    sequence — its first child is a ``- ...`` item at ``key_line``'s own indent
    (YAML lets a sequence value share its key's indentation) — sibling items at
    that same indent are also children; the block then ends at the first line
    that dedents or is a same-indent non-item (a sibling mapping key). Blank
    lines interior to the block are included; a trailing run of blank lines
    after the last child is excluded. Used to delete a block whole.
    """
    key_indent = line_indent(source_lines[key_line - 1])
    compact = first_child_indent(source_lines, key_line) == key_indent
    last = key_line
    for idx in range(key_line, len(source_lines)):
        line = source_lines[idx]
        if line.strip() == "":
            continue
        indent = line_indent(line)
        if indent > key_indent:
            last = idx + 1
            continue
        if compact and indent == key_indent and _is_seq_item(line):
            last = idx + 1
            continue
        break
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


# --- Edit collection across a file's findings -----------------------------


@dataclass(frozen=True)
class FixResult:
    """The outcome of collecting fixers' edits for a single file.

    ``edits`` are non-conflicting and ready to splice via :func:`apply_edits`.
    ``fixed`` are the findings whose edits were accepted; ``manual`` are the
    findings left for the user — report-only rules, per-occurrence refusals, and
    findings dropped because their edit conflicted with another's. ``caveats``
    holds the deduplicated ``(rule_id, caveat)`` pairs for the behavior-changing
    edits among ``edits``, in first-seen order, for the dry-run banner.
    """

    edits: list[TextEdit] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    manual: list[Finding] = field(default_factory=list)
    caveats: list[tuple[str, str]] = field(default_factory=list)


def _spans_conflict(a: tuple[int, int], b: tuple[int, int]) -> bool:
    """Return whether two ``(begin, end)`` offset spans conflict.

    The danger cases, by edit shape:

    - **Two pure insertions** (both zero-width) never conflict — even at the same
      point they splice as independent, well-formed lines (e.g. CL-0007's
      ``read_only`` and CL-0003's ``security_opt``, both inserted as a service's
      first child). They are *not* refused.
    - **An insertion touching a non-empty region's closed interval**
      (``begin <= point <= end``) *is* a conflict. The motivating case: CL-0003
      appends an entry at the line just after a ``security_opt`` block that
      CL-0009 is collapsing whole — the insertion point equals the deletion's end
      boundary, so applying both would orphan the appended entry beside the
      removed parent key. :func:`apply_edits` uses half-open overlap and would
      not catch this touch, so it is caught here (ADR-014: refuse, never guess).
    - **Two non-empty regions** conflict on half-open overlap only; adjacency
      (one ending exactly where the next begins) composes fine and is allowed,
      matching :func:`apply_edits`.
    """
    a_empty = a[0] == a[1]
    b_empty = b[0] == b[1]
    if a_empty and b_empty:
        return False
    if a_empty or b_empty:
        point, lo, hi = (a[0], b[0], b[1]) if a_empty else (b[0], a[0], a[1])
        return lo <= point <= hi
    return a[0] < b[1] and b[0] < a[1]


def collect_edits(
    findings: Iterable[Finding],
    data: dict[str, Any],
    lines: dict[str, int],
    text: str,
    *,
    only: set[str] | None = None,
) -> FixResult:
    """Gather every fixer's edits for one file, refusing conflicts.

    Each non-suppressed finding whose rule advertises a fixer is asked for its
    edits. Suppressed/service-excluded findings are skipped (suppression is a
    deliberate human decision; ADR-014). When ``only`` is given, findings whose
    rule id is not in it are ignored entirely. Findings whose fixer returns
    ``None`` (report-only or a per-occurrence refusal) go to ``manual``.

    Edits are then checked for conflicts across findings: if any edit of one
    finding conflicts with any edit of another (see :func:`_spans_conflict`),
    *both* findings are refused and moved to ``manual`` rather than guessing a
    merge. The surviving edits are returned ready to apply.
    """
    from compose_lint.rules import get_registered_rules

    rules_by_id = {}
    for rule_cls in get_registered_rules():
        rule = rule_cls()
        rules_by_id[rule.metadata.id] = rule

    candidates: list[tuple[Finding, list[TextEdit]]] = []
    manual: list[Finding] = []
    for finding in findings:
        if finding.suppressed:
            continue
        if only is not None and finding.rule_id not in only:
            continue
        matched = rules_by_id.get(finding.rule_id)
        if matched is None:
            continue
        edits = matched.fix(finding, data, lines, text)
        if edits:
            candidates.append((finding, edits))
        else:
            manual.append(finding)

    starts = _line_starts(text)

    def spans_of(edits: list[TextEdit]) -> list[tuple[int, int]]:
        return [
            (
                _offset(starts, edit.start_line, edit.start_col),
                _offset(starts, edit.end_line, edit.end_col),
            )
            for edit in edits
        ]

    spanned = [(finding, edits, spans_of(edits)) for finding, edits in candidates]
    refused: set[int] = set()
    for i in range(len(spanned)):
        for j in range(i + 1, len(spanned)):
            if any(_spans_conflict(x, y) for x in spanned[i][2] for y in spanned[j][2]):
                refused.add(i)
                refused.add(j)

    result = FixResult()
    seen_caveats: set[tuple[str, str]] = set()
    for index, (finding, edits, _spans) in enumerate(spanned):
        if index in refused:
            result.manual.append(finding)
            continue
        result.fixed.append(finding)
        result.edits.extend(edits)
        for edit in edits:
            if edit.caveat and (finding.rule_id, edit.caveat) not in seen_caveats:
                seen_caveats.add((finding.rule_id, edit.caveat))
                result.caveats.append((finding.rule_id, edit.caveat))
    result.manual.extend(manual)
    return result


def render_file_diff(
    path: str,
    original: str,
    patched: str,
    caveats: list[tuple[str, str]],
) -> str:
    """Render the dry-run output for one file: caveat banner + unified diff.

    Returns ``""`` when ``original`` and ``patched`` are identical (no edits).
    Behavior-changing fixes are announced above the diff with a
    ``⚠ behavior-changing`` line per ADR-014 so a reader sees which edits could
    alter runtime behavior before deciding to ``--apply``.
    """
    diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=path,
            tofile=path,
        )
    )
    if not diff:
        return ""
    banner = "".join(
        f"⚠ behavior-changing · {rule_id}: {caveat}\n" for rule_id, caveat in caveats
    )
    return banner + diff
