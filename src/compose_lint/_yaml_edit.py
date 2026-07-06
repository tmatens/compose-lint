"""Shared YAML/text-edit primitives for compose-lint fixers (ADR-014, #377).

Extracted from ``fix.py`` so the rule modules can import them as an explicit
shared-primitive layer rather than reaching into the fix engine's internals;
``fix.py`` consumes them from here too. They operate on
``source_lines = text.splitlines(keepends=True)`` where a 1-indexed line ``n`` is
``source_lines[n - 1]``, so individual fixers infer indentation, block extent,
and refusal conditions the same way (ADR-014, Part 1: "a shared helper layer so
individual rules stay small") instead of each re-deriving them.
"""

from __future__ import annotations

from typing import Any

from compose_lint.models import TextEdit

# security_opt directives that disable a default platform profile — CL-0009's
# territory. Shared here so CL-0003 can decline to append into a block whose
# entries are *all* profile-disables: CL-0009 will act on those, and appending a
# survivor first would let a second `fix` pass delete them (breaking idempotency,
# ADR-014). Values are matched against `normalize_security_opt(opt)`.
DISABLED_SECURITY_PROFILES = frozenset(
    {"seccomp:unconfined", "apparmor:unconfined", "label:disable"}
)


def normalize_security_opt(opt: Any) -> str:
    """Canonicalize a ``security_opt`` entry for comparison.

    Docker accepts both separators for a ``security_opt`` directive —
    ``seccomp=unconfined`` ≡ ``seccomp:unconfined``, ``no-new-privileges=true`` ≡
    ``no-new-privileges:true`` (verified with ``docker compose config``, which
    accepts and preserves both). Rules and fixers compare against the colon form,
    so without normalizing the separator CL-0009 misses an ``=``-form disable
    (issue #277 F3) and CL-0003 fires on an already-hardened ``=``-form
    ``no-new-privileges`` (#277 P1). Lower-cases and rewrites only the first
    ``=`` (the key/value separator), leaving any ``=`` inside a value untouched.
    """
    return str(opt).strip().lower().replace("=", ":", 1)


def extends_targets(data: dict[str, Any]) -> set[str]:
    """Return the names of services another in-file service ``extends``.

    A base service must not have list-valued fields (``security_opt``,
    ``cap_add``, ...) auto-appended or created by a fixer: Docker append-merges
    the base's list into every service that ``extends`` it, so an item we add to
    the base can collide with one the child already declares — or one a fixer
    adds to a sibling — yielding a duplicate item Docker rejects. Our parser
    never resolves ``extends``, so that duplicate exists only post-merge, where
    neither the reparse guard nor ``verify_apply`` can see it. This mirrors the
    child-side ``"extends" in service_config`` refusal the per-finding fixers
    already carry (issue #277 C1).

    Only same-file targets count: an ``extends`` carrying a ``file:`` key points
    at a base in another file, so a like-named local service is not its target.
    Both the mapping form (``extends: {service: base}``) and the string short
    form (``extends: base``) are recognised.
    """
    services = data.get("services")
    if not isinstance(services, dict):
        return set()
    targets: set[str] = set()
    for _name, config in services.items():
        if not isinstance(config, dict):
            continue
        ext = config.get("extends")
        if isinstance(ext, str):
            targets.add(ext)
        elif isinstance(ext, dict) and not ext.get("file"):
            service = ext.get("service")
            if isinstance(service, str):
                targets.add(service)
    return targets


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
