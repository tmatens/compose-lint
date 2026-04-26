"""YAML parser for Docker Compose files with line number tracking."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


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
        if k == "__lines__":
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

    Mapping line numbers are stored in a ``__lines__`` key on the dict
    itself (stripped before returning to callers). Sequence line numbers
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


def _construct_mapping(loader: LineLoader, node: yaml.MappingNode) -> dict[str, Any]:
    loader.flatten_mapping(node)
    mapping: dict[str, Any] = {}
    line_map: dict[str, int] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)  # type: ignore[no-untyped-call]
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
        value = loader.construct_object(value_node)  # type: ignore[no-untyped-call]
        if isinstance(key, str):
            line_map[key] = key_node.start_mark.line + 1
        mapping[key] = value
    mapping["__lines__"] = line_map
    return mapping


def _construct_sequence(loader: LineLoader, node: yaml.SequenceNode) -> list[Any]:
    items: list[Any] = [
        loader.construct_object(item_node)  # type: ignore[no-untyped-call]
        for item_node in node.value
    ]
    loader._seq_lines[id(items)] = {
        i: item_node.start_mark.line + 1 for i, item_node in enumerate(node.value)
    }
    return items


LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)
LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG,
    _construct_sequence,
)


def _strip_lines(data: Any) -> Any:
    """Remove __lines__ metadata from parsed data at every depth.

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
                    if k != "__lines__"
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
    nested YAML can't exhaust the interpreter's recursion limit. The
    visited set keyed by id() collapses YAML anchor-shared subtrees so
    chained aliases can't fan out into O(branching^depth) work — each
    unique container is walked once under the first prefix that reaches
    it. Recorded line numbers come from the container's own __lines__
    map (mappings) or the loader's seq_lines sidecar (sequences), which
    are identical no matter which alias path arrived first, so rule
    lookups against any reachable path still resolve correctly for keys
    directly on that container.
    """
    seq_lines = seq_lines or {}
    lines: dict[str, int] = {}
    visited: set[int] = set()
    stack: list[tuple[Any, str]] = [(data, prefix)]
    while stack:
        current, current_prefix = stack.pop()
        if isinstance(current, dict):
            if id(current) in visited:
                continue
            visited.add(id(current))
            line_map = current.get("__lines__", {})
            for key, value in current.items():
                if key == "__lines__":
                    continue
                full_key = f"{current_prefix}.{key}" if current_prefix else key
                if key in line_map:
                    lines[full_key] = line_map[key]
                stack.append((value, full_key))
        elif isinstance(current, list):
            if id(current) in visited:
                continue
            visited.add(id(current))
            item_lines = seq_lines.get(id(current), {})
            for i, item in enumerate(current):
                full_key = f"{current_prefix}[{i}]"
                if i in item_lines:
                    lines[full_key] = item_lines[i]
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
        if name == "__lines__":
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
    file as plain Python dicts with __lines__ metadata stripped, and
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
    except OSError as e:
        raise ComposeError(f"Cannot read file: {e}") from e

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
