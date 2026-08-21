"""Compose document merge, with per-path provenance.

Compose merges more than one document in two places that turn out to be the
same place: multi-file overlays (``compose.yml`` + ``compose.override.yml``,
or repeated ``-f``) and ``extends:``. Every field behaviour probed against
``docker compose config`` is identical across the two, so one table serves
both — see ``tests/test_merge_semantics.py``, which re-derives this table from
the real binary rather than trusting the comments here.

The important part is that merging is *field-specific*, not structural. A
plain recursive "child wins, sequences concatenate" merge is wrong for Compose
in three separate ways:

* ``volumes`` and ``devices`` are keyed by their **container-side path**, so a
  child remounting ``/var/run/docker.sock`` from a harmless source *replaces*
  the parent's mount rather than adding to it. Concatenating leaves the
  parent's entry visible and reports a CRITICAL finding against a service that
  removed it.
* ``command`` and ``entrypoint`` are **replaced** wholesale, not appended.
* The append-style sequences (``cap_add``, ``dns``, ...) **deduplicate**.

Provenance falls out of the merge for free: the merge already decides, per
output path, which document supplied the winning value, so recording the file
alongside the line costs one dict write at each decision point. Because the
line map is flat and path-keyed (``services.web.volumes[0]`` -> line), the
provenance map is keyed the same way and rules never have to know it exists.

Values are merged **as written**. Compose normalises short volume syntax to
long form, list ``environment`` to a mapping, and so on; this module does not,
because every rule reads the spelling the user typed and a normalising merge
would change what they see on files that have no overlay at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = ["Document", "Merged", "SourcedLine", "merge_documents", "merge_values"]


class SourcedLine(int):
    """A line number that remembers which file it is a line number *in*.

    Rules receive a flat ``{path: line}`` map and hand the looked-up value
    straight to ``Finding.line``. They never see a document path, so after a
    merge there is nothing in a finding to say which of the merged files its
    line belongs to — and reverse-engineering it from the line number alone is
    ambiguous the moment two files have content at the same line.

    Subclassing ``int`` threads the answer through untouched: this *is* an int
    everywhere it is compared, sorted, formatted or serialised to JSON, so no
    rule, formatter or fixer needs to know it exists, while the one consumer
    that cares can read ``.source``. That is the whole of the cross-file
    provenance problem, and it costs no change to any of the 27 rules.
    """

    # No __slots__: CPython forbids a non-empty __slots__ on an int subclass
    # (the base is variable-length), so the attribute lives in a per-instance
    # dict. Line numbers are created once per path and never in a hot loop.
    source: str | None

    def __new__(cls, value: int, source: str | None = None) -> SourcedLine:
        obj = super().__new__(cls, value)
        obj.source = source
        return obj


# ---------------------------------------------------------------------------
# Field strategy table (empirically derived; see tests/test_merge_semantics.py)
# ---------------------------------------------------------------------------

# Sequences the child replaces outright. These are argv-shaped: appending to a
# command line would produce something the user never wrote.
_REPLACE_SEQ = frozenset({"command", "entrypoint"})

# Sequences that append, preserving base order, dropping exact duplicates.
_APPEND_SEQ = frozenset(
    {
        "cap_add",
        "cap_drop",
        "dns",
        "dns_search",
        "env_file",
        "expose",
        "extra_hosts",
        "group_add",
        "networks",
        "profiles",
        "security_opt",
        "tmpfs",
        "volumes_from",
    }
)

# Sequences keyed by an identity extracted from each entry: same key means the
# child's entry replaces the parent's, different keys append.
_KEYED_SEQ = frozenset({"volumes", "devices", "ports"})

# Fields accepting either a list of "K=V" strings or a mapping, keyed by name.
_KEY_VALUE_SEQ = frozenset({"environment", "labels", "sysctls", "depends_on"})


def _volume_key(entry: Any) -> str | None:
    """Container-side path of a volume entry, in either syntax."""
    if isinstance(entry, dict):
        target = entry.get("target")
        return target if isinstance(target, str) else None
    if isinstance(entry, str):
        parts = _split_outside_braces(entry)
        # "name" (anonymous/named volume, no target) has no container path to
        # key on; "src:tgt" and "src:tgt:mode" do.
        return parts[1] if len(parts) >= 2 else None
    return None


def _device_key(entry: Any) -> str | None:
    """Container-side path of a device entry."""
    if isinstance(entry, dict):
        target = entry.get("target")
        return target if isinstance(target, str) else None
    if isinstance(entry, str):
        parts = _split_outside_braces(entry)
        # A bare "/dev/x" maps to itself in the container.
        return parts[1] if len(parts) >= 2 else parts[0]
    return None


def _port_key(entry: Any) -> str | None:
    """Identity of a port entry: host ip, published port, target, protocol.

    Compose keeps two publishings of the same container port on different host
    ports (verified), so the key is the whole tuple rather than the target.
    """
    if isinstance(entry, dict):
        bits = [
            str(entry.get("host_ip", "")),
            str(entry.get("published", "")),
            str(entry.get("target", "")),
            str(entry.get("protocol", "tcp")),
        ]
        return "|".join(bits)
    if isinstance(entry, str):
        spec, _, proto = entry.partition("/")
        parts = _split_outside_braces(spec)
        if len(parts) == 3:
            host_ip, published, target = parts
        elif len(parts) == 2:
            host_ip, published, target = "", parts[0], parts[1]
        else:
            host_ip, published, target = "", "", parts[0]
        return "|".join([host_ip, published, target, proto or "tcp"])
    return None


_SEQ_KEYERS = {
    "volumes": _volume_key,
    "devices": _device_key,
    "ports": _port_key,
}


def _split_outside_braces(text: str) -> list[str]:
    """Split on ``:`` while ignoring colons inside ``${...}``.

    ``${DOCKER_SOCK:-/var/run/docker.sock}:/s`` must not split at the ``:-``.
    Mirrors ``parser._split_short_volume``, generalised to every field.
    """
    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for i, ch in enumerate(text):
        if ch == "{" and i and text[i - 1] == "$":
            depth += 1
            current.append(ch)
        elif ch == "}" and depth:
            depth -= 1
            current.append(ch)
        elif ch == ":" and not depth:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def _kv_name(entry: Any) -> str | None:
    """Variable/label name of a ``K=V`` string, or None if it isn't one."""
    if isinstance(entry, str):
        name, sep, _ = entry.partition("=")
        # A bare "FOO" (pass-through from the host environment) still keys on
        # its own name.
        return name if name else None
    return None


# ---------------------------------------------------------------------------
# Provenance-carrying merge
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Document:
    """One loaded Compose document, its flat line map, and its deletions."""

    path: str
    data: dict[str, Any]
    lines: dict[str, int]
    # Dotted paths this document deleted with `!reset`. The key is absent from
    # `data` (the parser drops it), so this is the only record that the document
    # asked for the *other* document's value to go away.
    resets: frozenset[str] = frozenset()


@dataclass
class Merged:
    """A merged document, with a line and a source file for every path."""

    data: dict[str, Any]
    lines: dict[str, int] = field(default_factory=dict)
    sources: dict[str, str] = field(default_factory=dict)

    def source_of(self, path: str) -> str | None:
        return self.sources.get(path)


@dataclass
class _Side:
    """One input to a merge step: a value plus where it came from."""

    value: Any
    doc: Document
    path: str


class _Recorder:
    """Collects line/source provenance while a merge walks the documents."""

    def __init__(self) -> None:
        self.lines: dict[str, int] = {}
        self.sources: dict[str, str] = {}

    def take(self, out_path: str, side: _Side | None) -> None:
        """Record that ``out_path`` was supplied by ``side``."""
        if side is None:
            return
        line = side.doc.lines.get(side.path)
        if line is not None:
            self.lines[out_path] = SourcedLine(line, side.doc.path)
        self.sources[out_path] = side.doc.path

    def take_subtree(self, out_path: str, side: _Side | None) -> None:
        """Record ``side``'s whole subtree as landing at ``out_path``.

        Used when one document supplies a value the other never mentions: the
        entire subtree below it keeps that document's lines, re-keyed onto the
        merged path (the two differ once a list index moves).

        ``side`` is optional so callers that merge without provenance (the
        ``extends:`` path) need no null-guard at every call site.
        """
        if side is None:
            return
        self.take(out_path, side)
        prefix = side.path
        for key, line in side.doc.lines.items():
            if key == prefix:
                continue
            # The document root has an empty path, under which *every* key is a
            # descendant. Without this case the separator check below indexes
            # key[0] — always a name character at the root — and silently copied
            # nothing, so a value neither document overrode lost its line.
            if not prefix:
                self.lines[key] = SourcedLine(line, side.doc.path)
                self.sources[key] = side.doc.path
                continue
            if key.startswith(prefix) and key[len(prefix)] in ".[":
                moved = out_path + key[len(prefix) :]
                self.lines[moved] = SourcedLine(line, side.doc.path)
                self.sources[moved] = side.doc.path


def merge_values(
    base: Any,
    over: Any,
    *,
    field_name: str = "",
    base_side: _Side | None = None,
    over_side: _Side | None = None,
    out_path: str = "",
    rec: _Recorder | None = None,
    memo: dict[tuple[int, int, str], Any] | None = None,
) -> Any:
    """Merge ``over`` onto ``base`` using Compose's per-field semantics.

    ``field_name`` is the Compose key these values sit under, which is what
    selects the strategy. Provenance recording is optional: callers that merge
    within a single document (``extends:``) pass no recorder.

    ``memo`` collapses repeated work on anchor-shared subtrees. YAML aliases
    make the document a DAG, not a tree, so without it a subtree reachable by
    *n* paths is re-merged once per path — an 805-byte file took 5.4s. It is
    only safe when no recorder is active: provenance is path-dependent, and a
    cached subtree would report whichever path reached it first.
    """
    if memo is not None and rec is None:
        cache_key = (id(base), id(over), field_name)
        cached = memo.get(cache_key)
        if cached is not None:
            return cached
        result = merge_values(
            base,
            over,
            field_name=field_name,
            base_side=base_side,
            over_side=over_side,
            out_path=out_path,
            rec=None,
            memo=None,
        )
        memo[cache_key] = result
        return result

    # A mapping merges key-by-key, recursively, whatever it sits under.
    if isinstance(base, dict) and isinstance(over, dict):
        return _merge_mappings(base, over, base_side, over_side, out_path, rec)

    if isinstance(base, list) and isinstance(over, list):
        return _merge_sequences(
            base, over, field_name, base_side, over_side, out_path, rec
        )

    # Key/value fields accept a list *or* a mapping, and Compose merges the two
    # forms together by name. Normalise the odd side into the other's shape.
    if field_name in _KEY_VALUE_SEQ and isinstance(base, (list, dict)):
        if isinstance(base, dict) and isinstance(over, list):
            return _merge_kv_mixed(base, over, base_side, over_side, out_path, rec)
        if isinstance(base, list) and isinstance(over, dict):
            return _merge_kv_mixed_list_base(
                base, over, base_side, over_side, out_path, rec
            )

    # Scalars, and every type mismatch: the overriding document wins outright.
    if rec is not None and over_side is not None:
        rec.take_subtree(out_path, over_side)
    return over


def _merge_mappings(
    base: dict[str, Any],
    over: dict[str, Any],
    base_side: _Side | None,
    over_side: _Side | None,
    out_path: str,
    rec: _Recorder | None,
) -> dict[str, Any]:
    merged = dict(base)

    # `logging` is the one mapping Compose does not merge naively: options
    # belong to a driver, so naming a *different* driver discards the parent's
    # options rather than carrying them onto a driver that never defined them.
    drop_keys: set[str] = set()
    # `!reset` in the overriding document deletes the inherited key outright.
    if over_side is not None and over_side.doc.resets:
        for key in base:
            if _join(over_side.path, key) in over_side.doc.resets:
                drop_keys.add(key)
    if _leaf(out_path) == "logging":
        new_driver = over.get("driver")
        if new_driver is not None and new_driver != base.get("driver"):
            drop_keys.add("options")

    for key in base:
        if key in drop_keys:
            merged.pop(key, None)
            continue
        if key not in over and rec is not None and base_side is not None:
            rec.take_subtree(_join(out_path, key), _child(base_side, key))

    for key, value in over.items():
        child_out = _join(out_path, key)
        over_child = _child(over_side, key) if over_side else None
        if key in base and key not in drop_keys:
            # Seed the key's own location from the base before merging. A key
            # both documents mention is otherwise never recorded: the branches
            # above only fire for keys unique to one side, and the recursion
            # below records this key's *children*, not the key itself. That lost
            # the line of every container present in both files — including
            # `services.<name>`, which is where an absence-rule fixer inserts.
            #
            # Seeding is safe because the merge overwrites it wherever the
            # overriding document actually wins: a scalar re-records from
            # `over`, and a merged mapping or sequence keeps the base's line,
            # which is the file the key is written in.
            if rec is not None and base_side is not None:
                rec.take(child_out, _child(base_side, key))
            merged[key] = merge_values(
                base[key],
                value,
                field_name=key,
                base_side=_child(base_side, key) if base_side else None,
                over_side=over_child,
                out_path=child_out,
                rec=rec,
            )
        else:
            merged[key] = value
            if rec is not None and over_child is not None:
                rec.take_subtree(child_out, over_child)
    return merged


def _merge_sequences(
    base: list[Any],
    over: list[Any],
    field_name: str,
    base_side: _Side | None,
    over_side: _Side | None,
    out_path: str,
    rec: _Recorder | None,
) -> list[Any]:
    leaf = field_name or _leaf(out_path)

    if leaf in _REPLACE_SEQ:
        if rec is not None and over_side is not None:
            rec.take_subtree(out_path, over_side)
        return list(over)

    if leaf in _KEYED_SEQ:
        return _merge_keyed(
            base, over, _SEQ_KEYERS[leaf], base_side, over_side, out_path, rec
        )

    if leaf in _KEY_VALUE_SEQ:
        return _merge_keyed(base, over, _kv_name, base_side, over_side, out_path, rec)

    # Default for a Compose sequence is append-with-dedup. Anything not in the
    # tables above lands here, which matches every append-style field probed.
    return _merge_appended(base, over, base_side, over_side, out_path, rec)


def _merge_keyed(
    base: list[Any],
    over: list[Any],
    keyer: Any,
    base_side: _Side | None,
    over_side: _Side | None,
    out_path: str,
    rec: _Recorder | None,
) -> list[Any]:
    """Merge two sequences by entry identity: same key replaces, new key appends.

    Order follows Compose: surviving base entries keep their relative order,
    then the child's genuinely-new entries, in the order the child wrote them.
    """
    over_by_key: dict[str, int] = {}
    for i, entry in enumerate(over):
        key = keyer(entry)
        if key is not None:
            over_by_key[key] = i

    result: list[Any] = []
    origins: list[tuple[_Side | None, int]] = []
    consumed: set[int] = set()

    for i, entry in enumerate(base):
        key = keyer(entry)
        if key is not None and key in over_by_key:
            j = over_by_key[key]
            consumed.add(j)
            result.append(over[j])
            origins.append((over_side, j))
        else:
            result.append(entry)
            origins.append((base_side, i))

    for j, entry in enumerate(over):
        if j in consumed:
            continue
        result.append(entry)
        origins.append((over_side, j))

    _record_items(result, origins, out_path, rec)
    return result


def _merge_appended(
    base: list[Any],
    over: list[Any],
    base_side: _Side | None,
    over_side: _Side | None,
    out_path: str,
    rec: _Recorder | None,
) -> list[Any]:
    result: list[Any] = []
    origins: list[tuple[_Side | None, int]] = []
    seen: list[Any] = []

    for source_side, items in ((base_side, base), (over_side, over)):
        for i, entry in enumerate(items):
            if any(entry == prior for prior in seen):
                continue
            seen.append(entry)
            result.append(entry)
            origins.append((source_side, i))

    _record_items(result, origins, out_path, rec)
    return result


def _merge_kv_mixed(
    base: dict[str, Any],
    over: list[Any],
    base_side: _Side | None,
    over_side: _Side | None,
    out_path: str,
    rec: _Recorder | None,
) -> dict[str, Any]:
    """Mapping base, list override: fold the list's entries in by name."""
    merged = dict(base)
    for i, entry in enumerate(over):
        name = _kv_name(entry)
        if name is None:
            continue
        _, sep, value = str(entry).partition("=")
        merged[name] = value if sep else None
        if rec is not None and over_side is not None:
            rec.take(_join(out_path, name), _index(over_side, i))
    if rec is not None and base_side is not None:
        for key in base:
            if key not in {_kv_name(e) for e in over}:
                rec.take_subtree(_join(out_path, key), _child(base_side, key))
    return merged


def _merge_kv_mixed_list_base(
    base: list[Any],
    over: dict[str, Any],
    base_side: _Side | None,
    over_side: _Side | None,
    out_path: str,
    rec: _Recorder | None,
) -> list[Any]:
    """List base, mapping override: keep the list shape the file already uses."""
    as_list = [f"{k}={v}" if v is not None else str(k) for k, v in over.items()]
    return _merge_keyed(base, as_list, _kv_name, base_side, over_side, out_path, rec)


def _record_items(
    result: list[Any],
    origins: list[tuple[_Side | None, int]],
    out_path: str,
    rec: _Recorder | None,
) -> None:
    """Re-key each surviving item's provenance onto its merged index."""
    if rec is None:
        return
    for out_index, (side, in_index) in enumerate(origins):
        if side is None:
            continue
        rec.take_subtree(f"{out_path}[{out_index}]", _index(side, in_index))


def _child(side: _Side | None, key: Any) -> _Side | None:
    if side is None:
        return None
    value = side.value.get(key) if isinstance(side.value, dict) else None
    return _Side(value, side.doc, _join(side.path, key))


def _index(side: _Side, i: int) -> _Side:
    value = (
        side.value[i] if isinstance(side.value, list) and i < len(side.value) else None
    )
    return _Side(value, side.doc, f"{side.path}[{i}]")


def _join(prefix: str, key: Any) -> str:
    return f"{prefix}.{key}" if prefix else str(key)


def _leaf(path: str) -> str:
    """Last mapping key in a dotted path, ignoring list indices."""
    tail = path.rsplit(".", 1)[-1]
    return tail.split("[", 1)[0]


def merge_documents(documents: list[Document]) -> Merged:
    """Fold documents left to right, later documents overriding earlier ones."""
    if not documents:
        return Merged(data={})

    first = documents[0]
    rec = _Recorder()
    merged_data: dict[str, Any] = dict(first.data)
    base_side = _Side(first.data, first, "")
    rec.take_subtree("", base_side)
    # take_subtree on the root records "" itself; the root has no line.
    rec.lines.pop("", None)
    rec.sources.pop("", None)

    accumulated = first
    for nxt in documents[1:]:
        over_side = _Side(nxt.data, nxt, "")
        rec_next = _Recorder()
        # The accumulated document carries the *merged* line/source maps, so a
        # third file merges against provenance already resolved for the first
        # two rather than against the original first file.
        acc_doc = Document(path=accumulated.path, data=merged_data, lines=rec.lines)
        merged_data = _merge_mappings(
            merged_data,
            nxt.data,
            _Side(merged_data, acc_doc, ""),
            over_side,
            "",
            rec_next,
        )
        # Sources for paths the newer document did not touch stay as they were.
        carried = dict(rec.sources)
        carried.update(rec_next.sources)
        rec = _Recorder()
        rec.lines = rec_next.lines
        rec.sources = carried
        accumulated = acc_doc

    return Merged(data=merged_data, lines=rec.lines, sources=rec.sources)
