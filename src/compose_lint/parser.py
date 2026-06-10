"""YAML parser for Docker Compose files with line number tracking."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml


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

    Returns either a fragment/v1 ComposeNotApplicableError (file parses
    but the linter doesn't apply) or a plain ComposeError (file shape is
    not recognisable as Compose at all). See ADR-013 for the heuristic.
    """

    def _is_meta(k: Any) -> bool:
        if k is _LINES:
            return True
        if not isinstance(k, str):
            return False
        return k in _TOP_LEVEL_FRAGMENT_KEYS or k.startswith("x-")

    non_meta = [k for k in data if not _is_meta(k)]
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
        key = loader.construct_object(key_node)
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


def _construct_mapping(loader: LineLoader, node: yaml.MappingNode) -> dict[Any, Any]:
    _reject_duplicate_keys(loader, node)
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    line_map: dict[str, int] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
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
    (issue #277 B1). compose-lint only needs the underlying value to lint, so we
    construct the node as if the tag were absent — delegating to the
    line-capturing map/seq constructors so line tracking still works inside an
    overridden block, and re-resolving a scalar's implicit type so
    ``!override 8080`` stays an int and ``!reset null`` stays None.
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
# Compose override-file tags: parse the value, ignore the merge directive.
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
                    lines[full_key] = line_map[key]
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
                    lines[full_key] = item_lines[i]
                if first:
                    stack.append((item, full_key))
    return lines


def _validate_compose(data: Any) -> dict[str, Any]:
    """Validate that parsed YAML is a Docker Compose file."""
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
        if not isinstance(config, dict):
            raise ComposeError(
                f"Not a valid Compose file: service '{name}' must be a mapping"
            )

    return data


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
        content = filepath.read_text(encoding="utf-8")
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

    return loads(content)


def loads(content: str) -> tuple[dict[str, Any], dict[str, int]]:
    """Parse and validate Compose from an in-memory string.

    The string form of :func:`load_compose`: identical YAML parsing, line
    capture, and Compose validation, but with no filesystem read. This lets the
    fix engine re-parse its own candidate output before persisting it (ADR-014's
    "leave a valid Compose file" safety net) without round-tripping through a
    temporary file.

    Raises:
        ComposeError: If the text is not valid YAML or not a valid Compose file.
    """
    # LineLoader is a yaml.SafeLoader subclass — this call cannot
    # deserialize arbitrary Python objects. The assertion makes that
    # invariant explicit so a future refactor can't silently break it.
    assert issubclass(LineLoader, yaml.SafeLoader)  # noqa: S101
    # Instantiate explicitly (instead of yaml.load) so we can read the
    # per-load seq_lines sidecar after parsing finishes.
    loader = LineLoader(content)  # noqa: S506  # nosec B506 - SafeLoader subclass
    try:
        raw = loader.get_single_data()
        seq_lines = loader._seq_lines
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
        loader.dispose()  # type: ignore[no-untyped-call]

    if raw is None:
        raise ComposeError("Not a valid Compose file: file is empty")

    _validate_compose(raw)

    lines = _collect_lines(raw, seq_lines)
    data = _strip_lines(raw)

    return data, lines
