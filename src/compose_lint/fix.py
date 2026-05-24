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

from compose_lint.models import Finding, Severity, TextEdit

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
    Two coincident insertions (same zero-width point) order deterministically by
    their replacement text, so the result never depends on the order findings
    arrived in. An empty ``edits`` list returns ``text`` unchanged.
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
    # Region first; the replacement is a final, content-derived tiebreak so
    # coincident insertions order deterministically. Rule id would be ideal but
    # is not carried on a TextEdit at the splice layer (issue #261 L2).
    spans.sort(key=lambda span: (span[0], span[1], span[2].replacement))

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
    """Return the number of leading spaces on ``line`` (newline-insensitive).

    Counts spaces only; a tab would not be measured as indentation. This is
    safe because :func:`compose_lint.parser.load_compose` rejects tab
    indentation before any fixer runs, so the fixers never see it (issue
    #261 L3).
    """
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

    Uses the first ``:`` on the line, so a quoted key that itself contains a
    colon (``"a:b":``) is read as having an inline value and returns ``False``.
    That is a safe over-refusal — the fixer falls back to manual review rather
    than mis-editing — and the shape is rare (issue #261 L4).
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


def _is_blank_or_comment(line: str) -> bool:
    """Return whether ``line`` is blank or a full-line ``#`` comment.

    The block-shaping helpers below skip these uniformly. Neither a blank line
    nor a comment contributes to a block's structure, so neither should set an
    indent baseline, terminate a span, or be mistaken for a child. Handling them
    inconsistently is the root cause of issue #261 H2/H3 (a comment interior to a
    block truncated :func:`block_span`; a mis-indented comment poisoned the child
    baseline in the anchor/merge guards). Inline comments (``key: value  # ...``)
    are not full-line comments — those lines start with the key, not ``#``.
    """
    stripped = line.strip()
    return stripped == "" or stripped.startswith("#")


def first_child_indent(source_lines: list[str], key_line: int) -> int | None:
    """Return the indentation of the first child line under ``key_line``.

    Walks forward from the line after ``key_line`` to the first non-blank line.
    Returns its indent if it is a child, otherwise ``None`` — meaning the block
    has no children (the next content is a sibling or dedent). A line is a child
    when it is indented deeper than ``key_line`` *or* it sits at ``key_line``'s
    own indent and is a block-sequence item (``- ...``): YAML lets a sequence
    value share its key's indentation (the "compact" style), and those items are
    still children of the key. Blank lines and full-line comments are skipped —
    neither establishes block structure (issue #261).
    """
    key_indent = line_indent(source_lines[key_line - 1])
    for raw in source_lines[key_line:]:
        if _is_blank_or_comment(raw):
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
    child indent — are considered. Blank lines and full-line comments are skipped
    so neither can set the child-indent baseline (issue #261 H3).
    """
    key_indent = line_indent(source_lines[key_line - 1])
    child_indent: int | None = None
    for raw in source_lines[key_line:]:
        if _is_blank_or_comment(raw):
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
    Blank lines and full-line comments are skipped so neither can set the
    child-indent baseline (issue #261 H3).
    """
    key_indent = line_indent(source_lines[key_line - 1])
    child_indent: int | None = None
    for raw in source_lines[key_line:]:
        if _is_blank_or_comment(raw):
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
    lines and full-line comments interior to the block are included; a trailing
    run of either after the last child is excluded. A comment is skipped rather
    than treated as a dedent, so one sitting between a key and its child no
    longer truncates the span (issue #261 H2). Used to delete a block whole.
    """
    key_indent = line_indent(source_lines[key_line - 1])
    compact = first_child_indent(source_lines, key_line) == key_indent
    last = key_line
    for idx in range(key_line, len(source_lines)):
        line = source_lines[idx]
        if _is_blank_or_comment(line):
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


def replace_lines(
    source_lines: list[str],
    first: int,
    last: int,
    replacement: str,
    *,
    caveat: str | None = None,
) -> TextEdit:
    """Return a :class:`TextEdit` that replaces lines ``first``..``last`` whole.

    The region runs from the start of ``first`` to the start of the line after
    ``last`` (its trailing newline included), so ``replacement`` substitutes for
    those lines entirely. When ``last`` is the final line of a file with no
    trailing newline, the region ends at that line's end instead (there is no
    following line to anchor to) and a trailing newline on ``replacement`` is
    dropped so the file does not gain one it never had. :func:`delete_lines` is
    the empty-``replacement`` special case.
    """
    if last < len(source_lines):
        return TextEdit(first, 1, last + 1, 1, replacement, caveat=caveat)
    # `last` is the final line: end at its end (its newline, if any, included).
    end_col = len(source_lines[last - 1]) + 1
    if replacement.endswith("\n") and not source_lines[last - 1].endswith("\n"):
        replacement = replacement[:-1]
    return TextEdit(first, 1, last, end_col, replacement, caveat=caveat)


def delete_lines(
    source_lines: list[str],
    first: int,
    last: int,
    *,
    caveat: str | None = None,
) -> TextEdit:
    """Return a :class:`TextEdit` that removes lines ``first``..``last`` whole.

    The empty-``replacement`` case of :func:`replace_lines`: the region runs from
    the start of ``first`` to the start of the line after ``last`` so the trailing
    newline goes with the deleted lines (or to the final line's end when there is
    no following line to anchor to).
    """
    return replace_lines(source_lines, first, last, "", caveat=caveat)


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
    ``fixed_edits`` pairs each accepted finding with its own edits, in the same
    order as ``fixed``; the flattened ``edits`` loses that grouping, which
    per-finding consumers (SARIF ``artifactChanges``) need.
    """

    edits: list[TextEdit] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    manual: list[Finding] = field(default_factory=list)
    caveats: list[tuple[str, str]] = field(default_factory=list)
    fixed_edits: list[tuple[Finding, list[TextEdit]]] = field(default_factory=list)


def _spans_conflict(a: tuple[int, int], b: tuple[int, int]) -> bool:
    """Return whether two ``(begin, end)`` offset spans conflict.

    The danger cases, by edit shape:

    - **Two pure insertions** (both zero-width) never conflict — even at the same
      point they splice as independent, well-formed lines (e.g. CL-0007's
      ``read_only`` and CL-0003's ``security_opt``, both inserted as a service's
      first child). They are *not* refused.
    - **An insertion touching a non-empty region's *end*** (``lo < point <= hi``)
      *is* a conflict; touching its *start* (``point == lo``) is not. The
      motivating end case: CL-0003 appends an entry at the line just after a
      ``security_opt`` block that CL-0009 is collapsing whole — the insertion
      point equals the deletion's end boundary, so applying both would orphan the
      appended entry beside the removed parent key. :func:`apply_edits` uses
      half-open overlap and would not catch that touch, so it is caught here
      (ADR-014: refuse, never guess). An insertion at the *start* boundary lands
      before the deleted region and composes cleanly — it is exactly what
      :func:`apply_edits` already accepts — so refusing it only drops a safe fix
      (issue #261 L1).
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
        return lo < point <= hi
    return a[0] < b[1] and b[0] < a[1]


@dataclass(frozen=True)
class _FixUnit:
    """A group of findings resolved together by one set of edits.

    Most units pair a single finding with the edits its rule's fixer produced. A
    *coordinated* unit groups several findings across rules that one merged edit
    resolves jointly (see :func:`_coordinate_security_opt`). The unit is the
    granularity of conflict resolution: if its edits conflict with another unit's,
    *all* of its findings are refused together. ``caveat_rule_id`` attributes the
    units's caveats in the dry-run banner — the single finding's rule for a normal
    unit, or the behavior-changing rule for a coordinated one.
    """

    findings: list[Finding]
    edits: list[TextEdit]
    caveat_rule_id: str


# Caveat for the coordinated all-disable `security_opt` rewrite below. Defined
# here (not imported from CL-0009) because rule modules import `fix`, not the
# reverse; the wording covers the joint remove-disables + add-no-new-privileges
# edit rather than CL-0009's single-item removal.
_SECURITY_OPT_COORD_CAVEAT = (
    "Replacing the unconfined entries re-applies the default seccomp/AppArmor/"
    "SELinux profile; a workload that relies on a syscall the default profile "
    "blocks may fail."
)


def _coordinate_security_opt(
    service: str,
    svc_findings: list[Finding],
    data: dict[str, Any],
    lines: dict[str, int],
    source_lines: list[str],
) -> _FixUnit | None:
    """Merge CL-0003 + CL-0009 over one ``security_opt`` list into a single edit.

    Fires when a service's ``security_opt`` holds at least one profile-disable
    (a CL-0009 finding) and lacks ``no-new-privileges`` (a CL-0003 finding).
    Rewrites the whole item list to its surviving (non-disable) entries plus one
    ``- no-new-privileges:true``: CL-0009's removals and CL-0003's addition
    expressed as one edit, which re-lints clean for both rules.

    Doing it jointly resolves two cases the per-finding fixers cannot:

    - **All-disable** — every entry is a disable, so CL-0009 would have to empty
      the block and CL-0003 would have to append into a block of disables, each
      non-idempotent on its own (the only case coordinated before #261).
    - **Mixed with a trailing disable** — CL-0003's append point (the line after
      the list) meets the deletion of the last item when that item is a disable,
      so the per-finding fixers mutually refuse and the file never converges
      (issue #261 M1). A single edit has no internal boundary to collide on.

    Returns a coordinated :class:`_FixUnit` consuming both rules' findings, or
    ``None`` when the pattern does not apply or the block cannot be edited
    unambiguously: anchored/merged service, flow-style ``security_opt``, a list
    whose items do not map one-to-one onto source lines, an entry already naming
    ``no-new-privileges`` (e.g. ``:false`` — appending the true form would
    duplicate the key), or an item span holding anything but sequence items (an
    interleaved full-line comment a whole-span replacement would drop).
    """
    cl0003 = [f for f in svc_findings if f.rule_id == "CL-0003"]
    cl0009 = [f for f in svc_findings if f.rule_id == "CL-0009"]
    if not cl0003 or not cl0009:
        return None

    services = data.get("services")
    if not isinstance(services, dict):
        return None
    service_config = services.get(service)
    if not isinstance(service_config, dict):
        return None
    security_opt = service_config.get("security_opt")
    if not isinstance(security_opt, list) or not security_opt:
        return None
    if not any(
        str(opt).strip().lower() in DISABLED_SECURITY_PROFILES for opt in security_opt
    ):
        return None  # no profile-disable to remove: nothing to coordinate

    service_line = lines.get(f"services.{service}")
    so_line = lines.get(f"services.{service}.security_opt")
    n = len(source_lines)
    if service_line is None or so_line is None:
        return None
    if not (1 <= service_line <= n and 1 <= so_line <= n):
        return None
    if is_anchored_or_merged(source_lines, service_line):
        return None
    if not opens_block_body(source_lines[so_line - 1]):
        return None

    item_indent = first_child_indent(source_lines, so_line)
    if item_indent is None:
        return None
    _first, last = block_span(source_lines, so_line)
    if last <= so_line:
        return None  # `security_opt:` opened a body but has no item lines
    # The body must be only sequence items (and blanks); refuse if a comment or
    # other content sits among them so the whole-span replacement never drops it.
    if any(raw.strip() and not _is_seq_item(raw) for raw in source_lines[so_line:last]):
        return None

    # Map each parsed item to its (single, scalar) source line so the disable
    # test uses the resolved value (quotes resolved). A count mismatch means an
    # item we cannot place on one line — refuse rather than guess.
    item_lines = [i for i in range(so_line, last) if _is_seq_item(source_lines[i])]
    if len(item_lines) != len(security_opt):
        return None
    kept: list[str] = []
    for idx, opt in zip(item_lines, security_opt, strict=True):
        value = str(opt).strip().lower()
        if value in DISABLED_SECURITY_PROFILES:
            continue  # a disable CL-0009 removes
        if value.startswith("no-new-privileges"):
            # e.g. `no-new-privileges:false`: appending the true form would
            # duplicate the key (mirrors CL-0003's per-finding refusal).
            return None
        kept.append(source_lines[idx])

    # Surviving entries (verbatim, keeping any inline comments) plus one
    # no-new-privileges:true, as a single replacement so the removals and the
    # addition share no boundary to collide on.
    replacement = "".join(kept) + f"{' ' * item_indent}- no-new-privileges:true\n"
    edit = replace_lines(
        source_lines, so_line + 1, last, replacement, caveat=_SECURITY_OPT_COORD_CAVEAT
    )
    return _FixUnit([*cl0003, *cl0009], [edit], caveat_rule_id="CL-0009")


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

    Before the per-finding pass, a coordination pass groups cross-rule findings
    that one merged edit resolves jointly where each rule's own fixer would refuse
    (see :func:`_coordinate_security_opt`); consumed findings are not offered to
    their own fixers. Edits are then checked for conflicts across *units* (a unit
    is one finding's edits, or a coordinated group's): if any edit of one unit
    conflicts with any edit of another (see :func:`_spans_conflict`), *all* of
    both units' findings are refused and moved to ``manual`` rather than guessing
    a merge. The surviving edits are returned ready to apply.
    """
    from compose_lint.rules import get_registered_rules

    rules_by_id = {}
    for rule_cls in get_registered_rules():
        rule = rule_cls()
        rules_by_id[rule.metadata.id] = rule

    eligible = [
        finding
        for finding in findings
        if not finding.suppressed
        and (only is None or finding.rule_id in only)
        and finding.rule_id in rules_by_id
    ]

    source_lines = text.splitlines(keepends=True)

    # Coordination pass first, per service, so consumed findings skip their own
    # (refusing) fixers below.
    units: list[_FixUnit] = []
    consumed: set[int] = set()
    by_service: dict[str, list[Finding]] = {}
    for finding in eligible:
        by_service.setdefault(finding.service, []).append(finding)
    for service, svc_findings in by_service.items():
        unit = _coordinate_security_opt(
            service, svc_findings, data, lines, source_lines
        )
        if unit is not None:
            units.append(unit)
            consumed.update(id(finding) for finding in unit.findings)

    manual: list[Finding] = []
    for finding in eligible:
        if id(finding) in consumed:
            continue
        edits = rules_by_id[finding.rule_id].fix(finding, data, lines, text)
        if edits:
            units.append(_FixUnit([finding], edits, caveat_rule_id=finding.rule_id))
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

    spanned = [(unit, spans_of(unit.edits)) for unit in units]
    refused: set[int] = set()
    for i in range(len(spanned)):
        for j in range(i + 1, len(spanned)):
            if any(_spans_conflict(x, y) for x in spanned[i][1] for y in spanned[j][1]):
                refused.add(i)
                refused.add(j)

    result = FixResult()
    seen_caveats: set[tuple[str, str]] = set()
    for index, (unit, _spans) in enumerate(spanned):
        if index in refused:
            result.manual.extend(unit.findings)
            continue
        result.fixed.extend(unit.findings)
        result.edits.extend(unit.edits)
        for finding in unit.findings:
            result.fixed_edits.append((finding, unit.edits))
        for edit in unit.edits:
            if not edit.caveat:
                continue
            key = (unit.caveat_rule_id, edit.caveat)
            if key not in seen_caveats:
                seen_caveats.add(key)
                result.caveats.append(key)
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

    A content line without a trailing newline (a file with no final newline, the
    common Compose case) is followed by git's ``\\ No newline at end of file``
    marker. ``difflib`` omits it, which would otherwise glue that line and the
    next onto one line and garble the diff (issue #261 M2).
    """
    chunks: list[str] = []
    for line in difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile=path,
        tofile=path,
    ):
        # Header lines (`---`/`+++`/`@@`) always end in a newline; only a final
        # content line can lack one. Re-terminate it and add the git sentinel.
        if line.endswith("\n"):
            chunks.append(line)
        else:
            chunks.append(line + "\n\\ No newline at end of file\n")
    diff = "".join(chunks)
    if not diff:
        return ""
    banner = "".join(
        f"⚠ behavior-changing · {rule_id}: {caveat}\n" for rule_id, caveat in caveats
    )
    return banner + diff


def reparse_or_error(patched: str) -> str | None:
    """Return a parse-error message if ``patched`` is not valid Compose, else None.

    The fix engine's last safety net (ADR-014: a fixer must leave a valid Compose
    file). Re-parsing the combined candidate text before it is written turns a
    fixer bug from *silent corruption* into a *safe refusal* — it catches the
    whole class of "emits invalid YAML", including a shape no test has hit yet,
    rather than one bug at a time. The per-root-cause fixes (issue #261) still
    matter; this is the net under them for the unknown next one.

    It is deliberately a net, not a proof: parse success is weaker than
    non-destructive, so a fixer that drops an unrelated key or comment and still
    emits valid YAML passes this check. Catching *that* would need a structural
    before/after comparison, which is a separate, heavier mechanism.
    """
    from compose_lint.parser import ComposeError, loads

    try:
        loads(patched)
    except ComposeError as e:
        return str(e)
    return None


def _structural_drift(
    original: dict[str, Any],
    patched: dict[str, Any],
    fixed_services: set[str],
) -> str | None:
    """Return a message if ``patched`` changed anything outside the fixed services.

    Compares the two parsed trees, which carry plain Python types only (line
    numbers live in a separate map), so deep equality is a faithful test of
    "same configuration". Three things must hold for the patch to be confined to
    what the fixers claimed: every top-level key other than ``services`` is
    unchanged, the set of service names is unchanged, and every service the fix
    did *not* touch is deep-equal before and after. Returns ``None`` when only
    the fixed services differ, else the first violation found.
    """
    orig_top = {k: v for k, v in original.items() if k != "services"}
    new_top = {k: v for k, v in patched.items() if k != "services"}
    if orig_top != new_top:
        return "computed fix changed configuration outside services"

    orig_services = original.get("services") or {}
    new_services = patched.get("services") or {}
    if set(orig_services) != set(new_services):
        return "computed fix added or removed a service"

    for name, config in orig_services.items():
        if name in fixed_services:
            continue
        if config != new_services.get(name):
            return f"computed fix altered untouched service '{name}'"
    return None


def verify_apply(
    original_data: dict[str, Any],
    findings: list[Finding],
    result: FixResult,
    patched: str,
    *,
    only: set[str] | None = None,
    disabled_rules: dict[str, str | None] | None = None,
    severity_overrides: dict[str, Severity] | None = None,
    excluded_services: dict[str, dict[str, str | None]] | None = None,
) -> str | None:
    """Verify a patched candidate beyond "it parses" before it is written.

    The layer above :func:`reparse_or_error` (ADR-014). Re-parsing proves the
    output is *valid* Compose; it does not prove it is the *intended* Compose. A
    text splice with a miscomputed span can drop or mangle a neighbouring key and
    still emit valid YAML, which :func:`reparse_or_error` waves through. This
    re-runs the engine on the candidate and checks the three properties the
    corpus gate enforces pre-release but a live ``--apply`` could not, returning a
    diagnostic on the first failure (else ``None``):

    1. **Structure preserved** — every service the fix did not touch, and every
       top-level key outside ``services``, parses identically before and after
       (:func:`_structural_drift`). This is the cheap form of the check: it
       confirms untouched config is unchanged in the parsed tree, not that the
       *touched* services changed in exactly the intended way (that would need
       each fixer to declare its semantic delta — a heavier mechanism).
    2. **Converges** — a second collection on the candidate is a no-op, so a
       re-run of ``fix`` would not keep editing the file.
    3. **No new finding** — the candidate raises nothing the original did not, so
       a fix never trades one problem for another.

    Assumes ``patched`` already parses (the caller runs :func:`reparse_or_error`
    first); a parse failure here is reported as a verification failure all the
    same rather than raising.
    """
    from compose_lint.engine import run_rules
    from compose_lint.parser import ComposeError, loads

    try:
        re_data, re_lines = loads(patched)
    except ComposeError as e:  # pragma: no cover - reparse guard runs first
        return f"computed fix does not parse as Compose ({e})"

    drift = _structural_drift(original_data, re_data, {f.service for f in result.fixed})
    if drift is not None:
        return drift

    re_findings = run_rules(
        re_data,
        re_lines,
        disabled_rules=disabled_rules,
        severity_overrides=severity_overrides,
        excluded_services=excluded_services,
    )

    if collect_edits(re_findings, re_data, re_lines, patched, only=only).edits:
        return "computed fix does not converge: a second pass would still edit it"

    before = {(f.rule_id, f.service, f.message) for f in findings}
    new = sorted(
        {
            (f.rule_id, f.service)
            for f in re_findings
            if (f.rule_id, f.service, f.message) not in before
        }
    )
    if new:
        sample = ", ".join(f"{rule_id} on '{service}'" for rule_id, service in new[:2])
        return f"computed fix introduces a new finding ({sample})"

    return None
