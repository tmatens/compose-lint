"""YAML parser for Docker Compose files with line number tracking."""

from __future__ import annotations

import re
from pathlib import Path, PurePath
from typing import Any

import yaml

from compose_lint._lines import find_ambiguous_break
from compose_lint._merge import Document, Merged, merge_documents, merge_values
from compose_lint._safe_read import UnsafeFileError, read_text_bounded
from compose_lint.config import KNOWN_TOP_LEVEL_KEYS
from compose_lint.rules._interpolation import substitute_defaults


class _LinesKey:
    """Sentinel dict key under which a mapping's line map is stashed.

    A unique, non-string object so it can never collide with a YAML scalar key.
    Keying on the literal string ``"__lines__"`` silently dropped a service (or
    any key) genuinely named ``__lines__`` — a security linter skipping a
    service (issue #279 E2).
    """

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return "<__lines__>"


# The single shared sentinel instance used as the line-map key on every mapping.
_LINES = _LinesKey()


class ComposeError(Exception):
    """Raised when a file is not a valid Docker Compose file."""


class ComposeNotApplicableError(ComposeError):
    """Raised when a file parses as YAML but is not a v2/v3 Compose file.

    Covers Compose v1 files (services declared at top level, no `services:`
    wrapper; Docker retired Compose v1 in 2023) and structural fragments
    (e.g. files holding only `volumes:`, `networks:`, or `x-*` blocks for
    use with `extends:` or `-f` overlays). The CLI maps this to a per-file
    skip with exit 0, distinct from malformed input which still exits 2.
    See ADR-013.
    """


# Keys that v2/v3 Compose places at the top level alongside `services:`.
# A file containing only these (plus any `x-*` extension keys) is treated
# as a structural fragment when `services:` is absent.
_TOP_LEVEL_FRAGMENT_KEYS = frozenset(
    {"version", "name", "volumes", "networks", "configs", "secrets", "include"}
)

# Keys that, when present in a top-level mapping value, identify that
# value as a service definition. Drawn from the v1 Compose schema:
# https://docs.docker.com/reference/compose-file/legacy-versions/. Used
# only for v1 detection — v2/v3 files have a `services:` wrapper and
# never reach this check.
_V1_SERVICE_MARKERS = frozenset(
    {
        "image",
        "build",
        "command",
        "entrypoint",
        "ports",
        "volumes",
        "environment",
        "env_file",
        "depends_on",
        "container_name",
        "restart",
        "links",
        "expose",
        "working_dir",
        "user",
        "cap_add",
        "cap_drop",
        "privileged",
        "read_only",
        "devices",
        "security_opt",
        "network_mode",
        "networks",
        "extends",
    }
)


def _classify_missing_services(data: dict[str, Any]) -> ComposeError:
    """Decide which error subtype to raise when `services:` is absent.

    Returns either a fragment/v1/own-config ComposeNotApplicableError (file
    parses but the linter doesn't apply) or a plain ComposeError (file shape
    is not recognisable as Compose at all). See ADR-013 for the heuristic.
    """

    # `include` pulls services in from other files. compose-lint reads files
    # only and does not resolve it, so an include-only file is NOT a harmless
    # fragment — treating it as one produces a reassuring clean pass on a
    # deployable stack (issue #516). Refuse honestly instead.
    if "include" in data:
        return ComposeError(
            "Not a lintable target: this file uses 'include:', which pulls in "
            "services from other files. compose-lint reads files only and does "
            "not resolve include. Lint the merged output instead: "
            "docker compose config > merged.yml && compose-lint merged.yml"
        )

    def _is_meta(k: Any) -> bool:
        if k is _LINES:
            return True
        if not isinstance(k, str):
            return False
        return k in _TOP_LEVEL_FRAGMENT_KEYS or k.startswith("x-")

    non_meta = [k for k in data if not _is_meta(k)]
    if non_meta and all(k in KNOWN_TOP_LEVEL_KEYS for k in non_meta):
        return ComposeNotApplicableError(
            "Skipped: file appears to be a compose-lint config "
            f"(top-level {', '.join(f'{k!r}' for k in sorted(non_meta))} and no "
            "'services:' key), not a Compose file. compose-lint reads its config "
            "via --config; it is not a lint target."
        )
    if not non_meta:
        return ComposeNotApplicableError(
            "Skipped: file appears to be a Compose fragment "
            "(no 'services:' key; only top-level structural keys present). "
            "Fragments are typically merged via `extends:` or `-f` overlays "
            "and have no services to lint on their own."
        )
    if all(
        isinstance(data[k], dict)
        and any(marker in data[k] for marker in _V1_SERVICE_MARKERS)
        for k in non_meta
    ):
        return ComposeNotApplicableError(
            "Skipped: file appears to be Compose v1 "
            "(services declared at the top level, no 'services:' wrapper). "
            "Docker retired Compose v1 in 2023; compose-lint targets v2/v3. "
            "Migrate the file under a top-level `services:` key to enable linting."
        )
    return ComposeError("Not a valid Compose file: missing 'services' key")


class LineLoader(yaml.SafeLoader):
    """YAML loader that captures line numbers for mapping keys and sequence items.

    Subclasses ``yaml.SafeLoader``, so it inherits the safe constructor set
    and CANNOT instantiate arbitrary Python objects. Static analyzers that
    flag ``yaml.load(...)`` calls below as unsafe are false positives — the
    only overrides here are the mapping and sequence constructors, both of
    which record line numbers and otherwise delegate to the safe loader.

    Mapping line numbers are stored under a private non-string sentinel key
    (``_LINES``) on the dict itself (stripped before returning to callers), so
    they can't collide with a YAML key named ``__lines__``. Sequence line numbers
    can't live on the list (lists don't carry attributes and adding a
    sentinel item would change semantics), so they're stashed on the
    loader instance under ``_seq_lines``, keyed by ``id(list)``. The id
    keys are stable for the lifetime of the load because ``raw`` holds
    references to every constructed list, so nothing is GC'd until
    ``_collect_lines`` finishes.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # id(list) -> {index: line}
        self._seq_lines: dict[int, dict[int, int]] = {}
        # id(mapping) -> {key names carrying `!reset`}. The key is dropped from
        # the mapping (see `_construct_mapping`), so the only record that it was
        # ever written is here. A single file does not need it — a deleted key
        # is simply absent — but a *merge* does: `!reset` deletes the value the
        # other document supplies, and without this the base's value survives a
        # deletion Compose honours.
        self._resets: dict[int, set[str]] = {}
        # id(mapping) -> {key names carrying `!override`}. Like `!reset`, the
        # directive changes how the value *merges* rather than what it is, so a
        # single file needs no record of it — but a merge does: `!override`
        # replaces the other document's value instead of merging with it.
        self._overrides: dict[int, set[str]] = {}


def _mapping_key(loader: LineLoader, key_node: yaml.Node) -> Any:
    """Construct a mapping key, keeping non-string scalar keys as source text.

    Compose mapping keys (service names and every other key) are always strings;
    ``docker compose config`` keeps a key like ``yes`` or ``123`` verbatim while
    coercing only boolean-typed *values*. The retained YAML 1.1 resolvers (see
    ``_install_scalar_resolvers``) would otherwise turn a service named
    ``yes``/``on``/``123``/``null`` into ``True``/``int``/``None`` — which gets
    no line-map entry (line 218's ``isinstance(key, str)`` guard) and later
    crashes the formatters on the non-string ``Finding.service``. Using the
    source text matches Docker and keeps keys hashable strings.
    """
    key = loader.construct_object(key_node)
    if not isinstance(key, str) and isinstance(key_node, yaml.ScalarNode):
        return key_node.value
    return key


def _reject_duplicate_keys(loader: LineLoader, node: yaml.MappingNode) -> None:
    """Raise if a mapping declares the same key twice (issue #277 P2).

    Docker's loader rejects duplicate mapping keys; PyYAML silently lets the last
    value win, so ``privileged: true`` followed by ``privileged: false`` parsed
    clean and the line map pointed at the wrong occurrence. Matching Docker, this
    is a hard error.

    Runs *before* ``flatten_mapping`` so a merge key (``<<``) that legitimately
    reintroduces an overridden key is not mistaken for a duplicate — merge
    overrides only appear in ``node.value`` after flattening, and they are
    resolved by precedence, not rejected. Unhashable (complex ``? ...``) keys are
    skipped here; the construction loop surfaces them as their own error.
    """
    seen: set[Any] = set()
    for key_node, _value_node in node.value:
        if key_node.tag == "tag:yaml.org,2002:merge":
            continue  # the `<<` merge directive, not a data key
        key = _mapping_key(loader, key_node)
        try:
            duplicate = key in seen
        except TypeError:
            continue  # unhashable key — the construction loop reports it
        if duplicate:
            raise yaml.constructor.ConstructorError(
                None,
                None,
                f"found duplicate key {key!r}; Docker rejects duplicate mapping keys",
                key_node.start_mark,
            )
        seen.add(key)


_RESET_TAG = "!reset"
_OVERRIDE_TAG = "!override"


def _construct_mapping(loader: LineLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    _reject_duplicate_keys(loader, node)
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    line_map: dict[str, int] = {}
    for key_node, value_node in node.value:
        key = _mapping_key(loader, key_node)
        try:
            hash(key)
        except TypeError as e:
            # YAML's `? <complex>` syntax permits mappings and sequences as
            # keys. Compose files never use these, and letting an unhashable
            # key reach `mapping[key] = value` would raise a raw TypeError
            # that bypasses load_compose's ComposeError wrapping. Surface it
            # as a ConstructorError (subclass of YAMLError) so the public API
            # reports it the same way as any other malformed input.
            raise yaml.constructor.ConstructorError(
                None,
                None,
                f"found unhashable key of type {type(key).__name__!s}; "
                "Compose files may only use scalar keys",
                key_node.start_mark,
            ) from e
        if value_node.tag == _OVERRIDE_TAG and isinstance(key, str):
            loader._overrides.setdefault(id(mapping), set()).add(key)
        if value_node.tag == _RESET_TAG:
            if isinstance(key, str):
                loader._resets.setdefault(id(mapping), set()).add(key)
            # `!reset` deletes the key. Verified with `docker compose config`:
            # a file carrying `read_only: !reset true`, `cap_drop: !reset [ALL]`
            # and `security_opt: !reset [...]` deploys a service with *none* of
            # them. Constructing the value as if the tag were absent credited
            # the service with hardening Docker removes, so the absence rules
            # (CL-0003/0006/0007) stayed silent on an unhardened container.
            # Dropping the key models the deletion, which is what every rule
            # already knows how to grade.
            continue
        value = loader.construct_object(value_node)
        if isinstance(key, str):
            line_map[key] = key_node.start_mark.line + 1
        mapping[key] = value
    mapping[_LINES] = line_map
    return mapping


def _construct_sequence(loader: LineLoader, node: yaml.SequenceNode) -> list[Any]:
    items: list[Any] = [loader.construct_object(item_node) for item_node in node.value]
    loader._seq_lines[id(items)] = {
        i: item_node.start_mark.line + 1 for i, item_node in enumerate(node.value)
    }
    return items


def _construct_override_tag(loader: LineLoader, node: yaml.Node) -> Any:
    """Construct a node carrying a Compose override tag (``!reset``/``!override``).

    These are first-class Compose override-file syntax, not arbitrary YAML object
    tags: ``!override`` replaces a value instead of merging it, and ``!reset``
    drops an inherited value. A ``SafeLoader`` has no constructor for them, so it
    raises ``ConstructorError`` and a valid override file is reported broken
    (issue #277 B1).

    ``!override`` is constructed as if the tag were absent, which is correct for
    a single file: the directive changes how the value *merges*, not what it is.
    Verified with `docker compose config` — ``privileged: !override true``
    deploys ``privileged: true``.

    ``!reset`` in the value position of a mapping key never reaches here:
    :func:`_construct_mapping` drops the key outright, because the directive
    deletes it. This constructor still handles the tag in any other position so
    the document parses rather than erroring.

    Delegates to the line-capturing map/seq constructors so line tracking still
    works inside an overridden block, and re-resolves a scalar's implicit type
    so ``!override 8080`` stays an int.
    """
    if isinstance(node, yaml.MappingNode):
        return _construct_mapping(loader, node)
    if isinstance(node, yaml.SequenceNode):
        return _construct_sequence(loader, node)
    # Only a scalar node remains. Re-resolve its implicit type as if the tag were
    # absent so `!override 8080` stays an int and `!reset null` stays None.
    assert isinstance(node, yaml.ScalarNode)  # noqa: S101
    resolved_tag = loader.resolve(yaml.ScalarNode, node.value, (True, False))  # type: ignore[no-untyped-call]
    plain = yaml.ScalarNode(
        resolved_tag, node.value, node.start_mark, node.end_mark, node.style
    )
    return loader.construct_object(plain)


LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)
LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG,
    _construct_sequence,
)
# Compose override-file tags. `!override` keeps its value; `!reset` deletes the
# key it is attached to (see `_construct_mapping`).
LineLoader.add_constructor("!reset", _construct_override_tag)
LineLoader.add_constructor("!override", _construct_override_tag)


def _install_scalar_resolvers() -> None:
    """Rebuild LineLoader's implicit scalar resolvers without two YAML 1.1 traps.

    PyYAML's ``SafeLoader`` resolves plain scalars with YAML 1.1 rules, which
    mis-type two kinds of Compose value in security-relevant ways:

    * **Sexagesimal integers/floats.** ``22:22`` (and any ``H:C`` port whose
      sides are both <= 59) parses as the base-60 integer ``1342``, so CL-0005's
      ``str(port)`` finds no ``:`` and the published port escapes detection
      (issue #277 F1). The same alternative turns ``5:5``/``25:25``/``53:53``
      into integers.
    * **Timestamps.** A bare ``2024-01-01`` becomes a ``datetime.date``, which is
      not JSON-serializable (latent crash in the JSON/SARIF formatters) and
      breaks string-oriented rules.

    This rebuilds the resolver table from PyYAML's own patterns with the
    sexagesimal ``int``/``float`` alternatives removed and the ``timestamp``
    resolver dropped, leaving every other resolver byte-identical. Booleans keep
    their YAML 1.1 spelling (``yes``/``no``/``on``/``off`` as well as
    ``true``/``false``) deliberately: Docker's loader coerces those words to
    booleans for boolean-typed fields — ``docker compose config`` renders
    ``privileged: yes`` as ``privileged: true`` — so dropping them would make
    CL-0002/CL-0007 miss a hardening bypass Docker honors. Only ``LineLoader`` is
    re-tabled; the global ``yaml.SafeLoader`` is untouched.
    """
    LineLoader.yaml_implicit_resolvers = {}
    LineLoader.add_implicit_resolver(  # type: ignore[no-untyped-call]
        "tag:yaml.org,2002:bool",
        re.compile(
            r"""^(?:yes|Yes|YES|no|No|NO
                |true|True|TRUE|false|False|FALSE
                |on|On|ON|off|Off|OFF)$""",
            re.X,
        ),
        list("yYnNtTfFoO"),
    )
    LineLoader.add_implicit_resolver(  # type: ignore[no-untyped-call]
        "tag:yaml.org,2002:float",
        re.compile(
            r"""^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?
                |\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?
                |[-+]?\.(?:inf|Inf|INF)
                |\.(?:nan|NaN|NAN))$""",
            re.X,
        ),
        list("-+0123456789."),
    )
    LineLoader.add_implicit_resolver(  # type: ignore[no-untyped-call]
        "tag:yaml.org,2002:int",
        re.compile(
            r"""^(?:[-+]?0b[0-1_]+
                |[-+]?0[0-7_]+
                |[-+]?(?:0|[1-9][0-9_]*)
                |[-+]?0x[0-9a-fA-F_]+)$""",
            re.X,
        ),
        list("-+0123456789"),
    )
    LineLoader.add_implicit_resolver(  # type: ignore[no-untyped-call]
        "tag:yaml.org,2002:merge",
        re.compile(r"^(?:<<)$"),
        ["<"],
    )
    LineLoader.add_implicit_resolver(  # type: ignore[no-untyped-call]
        "tag:yaml.org,2002:null",
        re.compile(
            r"""^(?: ~
                |null|Null|NULL
                | )$""",
            re.X,
        ),
        ["~", "n", "N", ""],
    )
    LineLoader.add_implicit_resolver(  # type: ignore[no-untyped-call]
        "tag:yaml.org,2002:value",
        re.compile(r"^(?:=)$"),
        ["="],
    )


_install_scalar_resolvers()


def _strip_lines(data: Any) -> Any:
    """Remove line-map metadata (the ``_LINES`` sentinel key) at every depth.

    Iterative post-order traversal with an explicit work stack so
    pathologically-nested YAML can't exhaust the interpreter's recursion
    limit. The memo table keyed by object id() also collapses YAML
    anchor-shared subtrees into O(n) work instead of O(2^n).
    """
    if not isinstance(data, (dict, list)):
        return data

    _BUILD = object()
    memo: dict[int, Any] = {}
    stack: list[tuple[Any, ...]] = [(data,)]

    while stack:
        top = stack[-1]
        node = top[0]
        if len(top) == 1:
            if id(node) in memo:
                stack.pop()
                continue
            stack[-1] = (node, _BUILD)
            if isinstance(node, dict):
                for v in node.values():
                    if isinstance(v, (dict, list)) and id(v) not in memo:
                        stack.append((v,))
            elif isinstance(node, list):
                for item in node:
                    if isinstance(item, (dict, list)) and id(item) not in memo:
                        stack.append((item,))
        else:
            stack.pop()
            if isinstance(node, dict):
                memo[id(node)] = {
                    k: memo[id(v)] if isinstance(v, (dict, list)) else v
                    for k, v in node.items()
                    if k is not _LINES
                }
            else:
                memo[id(node)] = [
                    memo[id(item)] if isinstance(item, (dict, list)) else item
                    for item in node
                ]

    return memo[id(data)]


def _collect_lines(
    data: Any,
    seq_lines: dict[int, dict[int, int]] | None = None,
    prefix: str = "",
) -> dict[str, int]:
    """Collect line numbers into a flat dot-notation map.

    Iterative traversal with an explicit work stack so pathologically-
    nested YAML can't exhaust the interpreter's recursion limit.

    A container's own direct keys/items are recorded under *every* path that
    reaches it, but its children are pushed (its subtree walked) only the first
    time it is reached. This is the fix for issue #279 E3: when a service both
    defines an anchor and is aliased elsewhere, the alias and the
    anchor-definer reach the same shared dict, and the previous "skip the whole
    container on revisit" logic recorded the shared keys under only one of the
    two paths — so the other service's findings reported ``line=None`` (often
    the anchor-definer's, the most obvious location to a reader).

    Recording-per-path stays linear, not O(branching^depth): children are
    pushed once per unique container, so the number of (container, path) pops is
    bounded by the edge count of the unique-node DAG, not the number of
    root-to-node paths. The ``expanded`` set keyed by id() preserves the
    chained-alias DoS guard from issue #154. A shared subtree's *deeper* lines
    are still recorded under only its first-reached path; rule lookups are
    shallow (``services.<svc>.<key>``, with a list index falling back to the
    list's own line), so the direct-key recording covers them.
    """
    seq_lines = seq_lines or {}
    lines: dict[str, int] = {}
    expanded: set[int] = set()
    # Paths that two different nodes both claim. Joining path segments with "."
    # is lossy when a segment contains one: a service named `web.logging` and
    # service `web`'s `logging:` child both spell `services.web.logging`, and
    # last-write-wins handed one of them the other's line. A fixer then checked
    # its anchor/merge-key refusal against a different service's line, and an
    # edit every fixer is required to refuse was applied. Rather than return a
    # line belonging to somewhere else, drop the key: `lines.get` yields None,
    # which every consumer already treats as "cannot locate this — refuse".
    ambiguous: set[str] = set()

    def record(full_key: str, line: int) -> None:
        previous = lines.get(full_key)
        # The same node reached by two paths yields two different keys, so a
        # repeat with a *different* line is always a genuine collision.
        if previous is not None and previous != line:
            ambiguous.add(full_key)
        else:
            lines[full_key] = line

    stack: list[tuple[Any, str]] = [(data, prefix)]
    while stack:
        current, current_prefix = stack.pop()
        if isinstance(current, dict):
            first = id(current) not in expanded
            if first:
                expanded.add(id(current))
            line_map = current.get(_LINES, {})
            for key, value in current.items():
                if key is _LINES:
                    continue
                full_key = f"{current_prefix}.{key}" if current_prefix else key
                if key in line_map:
                    record(full_key, line_map[key])
                if first:
                    stack.append((value, full_key))
        elif isinstance(current, list):
            first = id(current) not in expanded
            if first:
                expanded.add(id(current))
            item_lines = seq_lines.get(id(current), {})
            for i, item in enumerate(current):
                full_key = f"{current_prefix}[{i}]"
                if i in item_lines:
                    record(full_key, item_lines[i])
                if first:
                    stack.append((item, full_key))
    for key in ambiguous:
        lines.pop(key, None)
    return lines


def _collect_tagged(
    data: Any, tagged: dict[int, set[str]], prefix: str = ""
) -> frozenset[str]:
    """Collect dot-notation paths of keys carrying a Compose merge directive.

    Walks the *raw* document (before :func:`_strip_lines` rebuilds it, which
    would invalidate the id() keys) with the same iterative work-stack shape as
    :func:`_collect_lines`.
    """
    if not tagged:
        return frozenset()
    found: set[str] = set()
    expanded: set[int] = set()
    stack: list[tuple[Any, str]] = [(data, prefix)]
    while stack:
        current, current_prefix = stack.pop()
        if isinstance(current, dict):
            for key in tagged.get(id(current), ()):
                found.add(f"{current_prefix}.{key}" if current_prefix else key)
            if id(current) in expanded:
                continue
            expanded.add(id(current))
            for key, value in current.items():
                if key is _LINES:
                    continue
                stack.append(
                    (value, f"{current_prefix}.{key}" if current_prefix else key)
                )
        elif isinstance(current, list):
            if id(current) in expanded:
                continue
            expanded.add(id(current))
            for i, item in enumerate(current):
                stack.append((item, f"{current_prefix}[{i}]"))
    return frozenset(found)


def _validate_compose(data: Any, *, merging: bool = False) -> dict[str, Any]:
    """Validate that parsed YAML is a Docker Compose file.

    ``merging`` relaxes the per-service check for a document that is one
    half of a merge, where a service may legitimately carry no body.
    """
    if not isinstance(data, dict):
        raise ComposeError(
            "Not a valid Compose file: expected a YAML mapping at the top level"
        )

    if "services" not in data:
        raise _classify_missing_services(data)

    services = data["services"]
    if not isinstance(services, dict):
        raise ComposeError("Not a valid Compose file: 'services' must be a mapping")

    for name, config in services.items():
        if name is _LINES:
            continue
        if config is None and merging:
            # `web:` with no body is a legal overlay half — verified against
            # `docker compose config`, which merges it as "no changes to web"
            # and deploys the base unaltered. Refusing it failed the *pair*,
            # so a valid stack did not lint at all. Standalone files keep the
            # stricter rule: a service with no body cannot run on its own.
            continue
        if not isinstance(config, dict):
            raise ComposeError(
                f"Not a valid Compose file: service '{name}' must be a mapping"
            )

    return data


def _merge_extends(
    base: Any, over: Any, memo: dict[tuple[int, int], Any] | None = None
) -> Any:
    """Merge a resolved ``extends`` base under an overriding child value.

    Follows Compose's ``extends`` semantics: child scalars win, mappings merge
    (child wins per key), sequences concatenate with the base first (Docker
    append-merges the base's list into every service that extends it).

    Memoized on the ``(id(base), id(over))`` pair, as ``_strip_lines`` and
    ``_collect_lines`` already are. YAML aliases make the document a DAG rather
    than a tree, so without a memo a subtree shared by *n* paths is re-merged
    once per path: an 805-byte file took 5.4 s, and 869 bytes took 21.5 s —
    4x per two alias levels, from a document PyYAML parses in 2 ms. The ids are
    stable for the call because ``data`` holds every node alive throughout.

    This does not subsume the recursion guard in :func:`loads`: memoizing
    removes repeated work, not depth, so a long chain still needs the
    ``RecursionError`` translation.
    """
    if memo is None:
        memo = {}
    key = (id(base), id(over))
    cached = memo.get(key)
    if cached is not None:
        return cached

    if isinstance(base, dict) and isinstance(over, dict):
        merged = dict(base)
        for child_key, value in over.items():
            merged[child_key] = (
                _merge_extends(base[child_key], value, memo)
                if child_key in base
                else value
            )
        memo[key] = merged
        return merged
    if isinstance(base, list) and isinstance(over, list):
        joined = [*base, *over]
        memo[key] = joined
        return joined
    return over


def _resolve_in_file_extends(data: dict[str, Any]) -> None:
    """Merge in-file ``extends`` targets into each service, in place.

    A service can inherit another's config via ``extends``. compose-lint reads
    files only, so it resolves the *in-file* forms — ``extends: <name>`` and
    ``extends: {service: <name>}`` — by merging the recursively-resolved target
    into the child. Without this, a child inheriting hardening is flagged for
    missing it and one inheriting a dangerous key is not flagged at all (issue
    #517). Cross-file ``extends: {file: ...}`` needs I/O we do not do and is
    left unresolved.

    The child's ``extends`` key is intentionally *kept* after merging: the
    fixers refuse to edit either side of an ``extends`` relationship (a text
    edit could create a post-merge duplicate Docker rejects), and that refusal
    keys on the ``extends`` marker still being present.
    """
    services = data.get("services")
    if not isinstance(services, dict):
        return
    resolved: dict[str, Any] = {}
    memo: dict[tuple[int, int, str], Any] = {}

    def _resolve(name: str, stack: tuple[str, ...]) -> Any:
        if name in resolved:
            return resolved[name]
        cfg = services[name]
        if not isinstance(cfg, dict):
            return cfg
        ext = cfg.get("extends")
        target: str | None = None
        if isinstance(ext, str):
            target = ext
        elif isinstance(ext, dict) and "file" not in ext:
            service = ext.get("service")
            if isinstance(service, str):
                target = service
        if (
            target is None
            or target not in services
            or not isinstance(services[target], dict)
            or name in stack  # cycle — stop rather than recurse forever
        ):
            resolved[name] = cfg
            return cfg
        parent = _resolve(target, (*stack, name))
        # Compose resolves `extends:` with the same field-specific merge it uses
        # for multi-file overlays (verified against `docker compose config` in
        # tests/test_merge_semantics.py), so both go through one table. The
        # previous concatenate-every-sequence merge reported a CRITICAL socket
        # mount against a child that had replaced it at the same mount point.
        merged = merge_values(parent, cfg, memo=memo)  # keeps child's `extends` marker
        resolved[name] = merged
        return merged

    for name in list(services):
        services[name] = _resolve(name, ())


def _lexical_join(base_dir: PurePath, source: str) -> str:
    """Join ``source`` onto ``base_dir`` lexically, in POSIX notation.

    Claims are deploy-host-independent (ADR-023), so the math is done on
    path *segments*, never through the lint host's path semantics. On a
    POSIX lint host the result is byte-identical to
    ``os.path.normpath(os.path.join(base_dir, source))`` — the behavior
    verified against Docker Compose 29.4.3. On Windows the drive or UNC
    anchor is dropped and the result is still ``/``-rooted: a climb that
    saturates the anchor names ``/`` — the root of whatever filesystem
    contains the compose file at deploy time, which is the fact the rules
    grade (the deploy host may be the Windows machine itself, where that
    root is the containing drive or share, or a Linux host the file is
    headed for, where it is ``/``).

    Compose sources use ``/`` separators on every platform, so tokens are
    split on ``/`` only; ``..`` saturates at the root, as ``normpath``
    does.
    """
    segments: list[str] = []
    base_tokens = base_dir.parts[1:] if base_dir.is_absolute() else base_dir.parts
    for token in (*base_tokens, *source.split("/")):
        if token in ("", "."):
            continue
        if token == "..":
            if segments:
                segments.pop()
            continue
        segments.append(token)
    return "/" + "/".join(segments)


def _resolved_bind_source(source: str, base_dir: PurePath) -> str | None:
    """The host path a relative or ``~`` bind source names, else ``None``.

    Compose resolves a relative source (``./x``, ``../x``, ``.``, ``..``)
    against the directory holding the compose file, and expands a leading
    ``~`` to the invoking user's home. Both verified against Docker Compose
    (29.4.3): a long-syntax bind with twelve ``..`` segments mounted the host
    root filesystem, and ``~:/probe`` mounted the home directory.

    Resolution is lexical segment math in POSIX notation on every platform
    (ADR-023): what a source names is a fact about the *document*, not about
    the machine that happens to be linting it — the same file is routinely
    linted on a laptop and deployed on a server. ``~`` sources are left as
    written on every platform: whose home ``~`` names is a deploy-host fact,
    and the rules claim the *spelling* instead (``~/.ssh`` is the deploying
    user's credential directory, whoever that is — see CL-0013), which made
    the old expand-against-the-linting-user proxy unnecessary (#602).

    ``~user`` is deliberately left as written, but *not* because Compose
    ignores it. Measured against Docker Compose 29.4.3: Compose strips the
    ``~`` and joins the remainder onto the invoking user's ``$HOME``, so
    ``~root/.ssh`` becomes ``$HOME/root/.ssh`` and ``~someone/x`` becomes
    ``$HOME/someone/x``. It never resolves another account's home directory.
    Reproducing that would mean asserting a host path from the *linting*
    user's environment for a spelling that almost always indicates the author
    meant a different account, so the source is left alone and no host path is
    claimed for it.

    Anything else — an absolute path, a named volume, an unresolved
    ``${VAR}``, a relative source with no absolute ``base_dir`` to resolve
    against — is returned as ``None`` and left exactly as written.
    """
    # Resolve "${VAR:-default}" first, so the shapes below see the path the
    # file actually ships. The two compose: "${DATA:-./data}" is a relative
    # source, "${SOCK:-/var/run/docker.sock}" an absolute one.
    substituted = substitute_defaults(source)
    if substituted is None:
        return None  # a reference with no default -- not knowable from this file
    if substituted != source:
        resolved = _resolved_bind_source(substituted, base_dir)
        # An absolute default resolves to itself, which the recursion reports as
        # None (nothing to rewrite); the substitution still has to be applied.
        return resolved if resolved is not None else substituted
    if source.startswith("~"):
        return None  # claimed by spelling in the rules, never expanded (#602)
    if source in {".", ".."} or source.startswith(("./", "../")):
        if not base_dir.is_absolute():
            return None
        return _lexical_join(base_dir, source)
    return None


def coverage_gaps(data: dict[str, Any]) -> list[str]:
    """Describe every part of ``data`` compose-lint could not actually lint.

    compose-lint reads single files and does no I/O to follow references out of
    them, so two spellings leave services ungraded: ``include:`` alongside
    ``services:`` (the included files' services are never seen) and
    ``extends: {file: ...}`` (the base is never merged, so the child is graded
    on its own keys only). Both are invisible in the result — the run reports a
    clean pass over a partial view, which for a merge gate is the one failure
    mode that matters.

    Returned as messages rather than raised, because the local services *can*
    still be linted usefully; the caller decides whether the gap is fatal. An
    ``include``-only file has no local services at all and is already rejected
    at parse time, which is the precedent this generalizes.
    """
    gaps: list[str] = []
    services = data.get("services")
    if "include" in data and isinstance(services, dict):
        gaps.append(
            "'include:' is not resolved, so services from the included files "
            "were not linted. Lint the merged output (docker compose config) "
            "to cover them, or pass --allow-partial-coverage to accept the gap."
        )
    if isinstance(services, dict):
        unmerged = sorted(
            name
            for name, config in services.items()
            if isinstance(config, dict)
            and isinstance(config.get("extends"), dict)
            and config["extends"].get("file")
        )
        if unmerged:
            listed = ", ".join(repr(name) for name in unmerged)
            gaps.append(
                f"cross-file 'extends: {{file: ...}}' is not resolved, so "
                f"{listed} {'was' if len(unmerged) == 1 else 'were'} graded "
                "without the inherited base. Lint the merged output "
                "(docker compose config) to cover it, or pass "
                "--allow-partial-coverage to accept the gap."
            )
    return gaps


def _substitute_interpolation_defaults(data: Any) -> None:
    """Rewrite every string leaf to the value Compose ships with no ``.env``.

    Classification has to happen *after* canonicalization, not before. With
    substitution wired into a single call site (bind sources), every other rule
    compared its dangerous-value set against the literal text ``"${P:-true}"``
    and found no match, while Compose deploys exactly ``true`` — verified with
    ``docker compose config`` for ``privileged``, ``network_mode``, ``user``,
    ``cap_add``, ``security_opt``, ``devices`` and image tags. Normalizing once
    here is what keeps that from being re-litigated per rule: a rule that adds a
    dangerous literal to its set gets the interpolated spellings for free, and
    cannot forget to.

    Only *values* are rewritten. Mapping keys are left alone because the
    ``lines`` map is keyed by the raw key path, and rewriting a key would break
    every line lookup that indexes it.

    A reference with no default (``${VAR}``) is left exactly as written:
    :func:`substitute_defaults` returns ``None`` for it, and inventing a value
    would invent a finding. Walks are memoized by ``id`` so a document built
    from YAML aliases is visited once per distinct object rather than once per
    path through the alias graph.
    """
    seen: set[int] = set()

    def resolve(value: str) -> str:
        substituted = substitute_defaults(value)
        return value if substituted is None else substituted

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if id(node) in seen:
                return
            seen.add(id(node))
            for key, value in node.items():
                if isinstance(value, str):
                    node[key] = resolve(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            if id(node) in seen:
                return
            seen.add(id(node))
            for index, value in enumerate(node):
                if isinstance(value, str):
                    node[index] = resolve(value)
                else:
                    walk(value)

    walk(data)


def _split_short_volume(volume: str) -> tuple[str, str, str]:
    """Split ``source:target[:mode]`` at the separator, ignoring ``${...}``.

    A plain ``partition(":")`` splits inside the substitution:
    ``${DOCKER_SOCKET_PATH:-/var/run/docker.sock}:/s`` has its first colon in
    the ``:-``, yielding a source of ``${DOCKER_SOCKET_PATH``. That silently
    skipped every ``:-`` default -- the commonest spelling by far -- while the
    ``-`` form worked, which is exactly the sort of near-miss that looks
    correct in a test written around one example.

    Returns the same 3-tuple shape as :meth:`str.partition`.
    """
    depth = 0
    for i, ch in enumerate(volume):
        if ch == "{" and i and volume[i - 1] == "$":
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
        elif ch == ":" and not depth:
            return volume[:i], ":", volume[i + 1 :]
    return volume, "", ""


def _resolve_bind_sources(data: dict[str, Any], base_dir: Path) -> None:
    """Rewrite relative and ``~`` bind sources to the host paths they name.

    Left as written, neither shape reaches the host-path rules: ``../../../..``
    matches no entry in any path list, and the short-syntax pattern does not
    recognise a non-absolute source as a bind mount at all. A bind spelled with
    enough ``..`` segments therefore mounted the host root filesystem — the
    live ``docker.sock`` included — and was reported as a clean pass, the same
    defect class as the whole-root mount spelled ``/.``.

    This belongs here rather than in the rules because this is the only place
    that knows where the file sits: rules receive the parsed document and never
    learn its path. :func:`_resolve_in_file_extends` resolves the same way, for
    the same reason.
    """
    services = data.get("services")
    if not isinstance(services, dict):
        return
    for service in services.values():
        if not isinstance(service, dict):
            continue
        volumes = service.get("volumes")
        if not isinstance(volumes, list):
            continue
        for i, volume in enumerate(volumes):
            if isinstance(volume, str):
                source, sep, rest = _split_short_volume(volume)
                if not sep:
                    continue  # a lone name is an anonymous volume, not a bind
                resolved = _resolved_bind_source(source, base_dir)
                if resolved is not None:
                    volumes[i] = f"{resolved}:{rest}"
            elif isinstance(volume, dict):
                source_value = volume.get("source")
                if isinstance(source_value, str):
                    resolved = _resolved_bind_source(source_value, base_dir)
                    if resolved is not None:
                        volume["source"] = resolved


def load_compose(
    path: str | Path,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Load and validate a Docker Compose file.

    Returns a tuple of (data, lines) where data is the parsed Compose
    file as plain Python dicts with the line-map metadata stripped, and
    lines is a flat dict mapping dot-notation paths to line numbers.

    Raises:
        ComposeError: If the file is not valid YAML or not a valid Compose file.
        FileNotFoundError: If the file does not exist.
    """
    filepath = Path(path)
    try:
        # newline="" disables universal-newline translation so the parser sees
        # the file's real bytes. read_text() would rewrite a lone \r (and CRLF)
        # to \n, which hid a lone \r from the ambiguous-break check below and,
        # worse, meant `check` and `fix` parsed *different* text for the same
        # file — `fix` has always read with newline="" to preserve line endings.
        # One read shape for both is the same principle as one line space.
        content = read_text_bounded(filepath, newline="")
    except UnsafeFileError as e:
        raise ComposeError(str(e)) from e
    except FileNotFoundError:
        raise
    except UnicodeDecodeError as e:
        # A non-UTF-8 file (e.g. latin-1) raises UnicodeDecodeError, a ValueError
        # subclass that the OSError handler below does not catch. Left uncaught it
        # would abort a whole directory sweep on one bad file; surface it as a
        # per-file ComposeError instead (issue #277 B2).
        raise ComposeError(f"Invalid encoding: file is not valid UTF-8 ({e})") from e
    except OSError as e:
        raise ComposeError(f"Cannot read file: {e}") from e

    # ``.absolute()`` first: the parent of a bare "docker-compose.yml" is ".",
    # and joining a relative source onto that leaves it relative, which is the
    # unresolved state this exists to remove.
    #
    # Deliberately *not* ``.resolve()``, which would follow symlinks. Compose
    # resolves a relative source lexically against the project directory as
    # given. Verified against Docker Compose 29.4.3: for a compose file reached
    # through a symlinked directory, "../etc" is the parent of the *link* path,
    # not of the link's target. Resolving physically named a different host path
    # than the one Compose actually mounts, in either direction.
    return loads(content, base_dir=filepath.absolute().parent)


def _loads_full(
    content: str, base_dir: Path | None = None, *, merging: bool = False
) -> tuple[dict[str, Any], dict[str, int], frozenset[str], frozenset[str]]:
    """Parse and validate Compose from an in-memory string.

    The string form of :func:`load_compose`: identical YAML parsing, line
    capture, and Compose validation, but with no filesystem read. This lets the
    fix engine re-parse its own candidate output before persisting it (ADR-014's
    "leave a valid Compose file" safety net) without round-tripping through a
    temporary file.

    ``base_dir`` is the directory the content came from, and is what relative
    and ``~`` bind sources resolve against (see :func:`_resolve_bind_sources`).
    Omitted, those sources are left as written — correct for a caller that has
    no file, such as the fix engine's validation re-parse.

    Raises:
        ComposeError: If the text is not valid YAML or not a valid Compose file.
    """
    # Refuse a document whose line numbering has no answer both sides agree on.
    # PyYAML breaks on a lone \r, U+0085, U+2028 and U+2029; editors, SARIF
    # viewers and CI annotators split on \n. compose-lint must report one line
    # number, and on such a document any choice is wrong for somebody — the fix
    # engine would splice at a line the user is not looking at. Refusing is the
    # only answer that cannot mislabel, and it costs nothing real: none of the
    # 5,417 files in the corpus contains one.
    ambiguous = find_ambiguous_break(content)
    if ambiguous is not None:
        line, description = ambiguous
        raise ComposeError(
            f"Ambiguous line break on line {line}: {description}. "
            "This is a line break to the YAML parser but not to editors, SARIF "
            "viewers or CI annotations, so no reported line number would be "
            "correct for both. Use LF or CRLF line endings and remove the "
            "character."
        )

    # LineLoader is a yaml.SafeLoader subclass — this call cannot
    # deserialize arbitrary Python objects. The assertion makes that
    # invariant explicit so a future refactor can't silently break it.
    assert issubclass(LineLoader, yaml.SafeLoader)  # noqa: S101
    # Constructing the loader is *inside* the try: `Reader.__init__` runs the
    # printable-character check, so a document carrying a C0 byte raises
    # `ReaderError` here rather than at `get_single_data()`. Built outside, that
    # walked straight past the fail-loud boundary and reached the CLI as an
    # unhandled traceback with exit 1.
    loader = None
    try:
        # Instantiate explicitly (instead of yaml.load) so we can read the
        # per-load seq_lines sidecar after parsing finishes.
        loader = LineLoader(content)  # noqa: S506  # nosec B506 - SafeLoader subclass
        raw = loader.get_single_data()
        seq_lines = loader._seq_lines
        raw_resets = loader._resets
        raw_overrides = loader._overrides
    except yaml.YAMLError as e:
        raise ComposeError(f"Invalid YAML: {e}") from e
    except RecursionError as e:
        # PyYAML's composer is recursive (compose_node -> compose_sequence_node
        # -> compose_node) with no built-in depth limit, so deeply-nested input
        # like `[[[[...]]]]` exhausts the interpreter stack from inside the
        # parser. RecursionError is a RuntimeError, not a YAMLError, so it
        # bypasses the wrapper above; surface it as ComposeError so the public
        # contract holds for all malformed input.
        raise ComposeError("Invalid YAML: input is too deeply nested") from e
    finally:
        if loader is not None:
            loader.dispose()  # type: ignore[no-untyped-call]

    if raw is None:
        raise ComposeError("Not a valid Compose file: file is empty")

    _validate_compose(raw, merging=merging)

    # The post-parse passes recurse too, and the guard above covered only the
    # parse. A 2000-deep `extends:` chain, or a self-referential
    # `${A:-${A:-...}}` in a bind source, exhausted the stack *after* the loader
    # returned: a raw traceback, exit 1 where the contract says 2, and every
    # later file in the batch never linted. The fail-loud boundary has to cover
    # each pass that walks the document, not only the one that builds it.
    try:
        lines = _collect_lines(raw, seq_lines)
        reset_paths = _collect_tagged(raw, raw_resets)
        override_paths = _collect_tagged(raw, raw_overrides)
        data = _strip_lines(raw)
        # Canonicalize before anything classifies: rules and the extends and
        # bind-source passes below all see the value the file actually ships
        # (see that function's docstring for why this is document-wide).
        _substitute_interpolation_defaults(data)
        _resolve_in_file_extends(data)
        if base_dir is not None:
            _resolve_bind_sources(data, base_dir)
    except RecursionError as e:
        raise ComposeError(
            "Invalid Compose file: resolving the document is too deeply nested "
            "(check for a long `extends:` chain or a self-referential "
            "`${VAR}` default)"
        ) from e

    return data, lines, reset_paths, override_paths


def loads(
    content: str, base_dir: Path | None = None
) -> tuple[dict[str, Any], dict[str, int]]:
    """Parse Compose from a string, returning ``(data, lines)``.

    The public string entry point. :func:`_loads_full` additionally reports the
    paths deleted by ``!reset``, which only a merge needs.
    """
    data, lines, _, _ = _loads_full(content, base_dir=base_dir)
    return data, lines


def load_document(path: str | Path) -> Document:
    """Load one Compose file as a :class:`Document` ready to merge.

    The merge-aware sibling of :func:`load_compose`: same parse, same
    validation, but it keeps the ``!reset`` deletions that only matter once a
    second document is folded in.
    """
    filepath = Path(path)
    try:
        content = read_text_bounded(filepath, newline="")
    except UnsafeFileError as e:
        raise ComposeError(str(e)) from e
    except UnicodeDecodeError as e:
        raise ComposeError(f"Invalid encoding: file is not valid UTF-8 ({e})") from e
    except OSError as e:
        raise ComposeError(f"Cannot read file: {e}") from e
    data, lines, resets, overrides = _loads_full(
        content, base_dir=filepath.absolute().parent, merging=True
    )
    return Document(
        path=str(path), data=data, lines=lines, resets=resets, overrides=overrides
    )


def load_merged(paths: list[str | Path]) -> Merged:
    """Load and merge several Compose files into the configuration Compose runs.

    Later paths override earlier ones, which is the order Compose itself uses
    for ``-f a -f b`` and for a base file plus its ``compose.override.yml``.
    """
    return merge_documents([load_document(p) for p in paths])


def merge_patched(
    patched: str, base_path: str | Path, overlays: list[str]
) -> tuple[dict[str, Any], dict[str, int]]:
    """Re-merge a candidate patch of ``base_path`` with its overlay documents.

    The verification counterpart of :func:`load_merged`. ``fix`` proposes an
    edit to the base file's *text*; the property that has to hold afterwards is
    about the document Compose would run, so the candidate is merged with the
    same overlays before the engine re-runs over it.
    """
    base_dir = Path(base_path).absolute().parent
    data, lines, resets, overrides = _loads_full(
        patched, base_dir=base_dir, merging=True
    )
    candidate = Document(
        path=str(base_path),
        data=data,
        lines=lines,
        resets=resets,
        overrides=overrides,
    )
    merged = merge_documents([candidate, *(load_document(p) for p in overlays)])
    return merged.data, merged.lines
