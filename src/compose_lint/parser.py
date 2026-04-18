"""YAML parser for Docker Compose files with line number tracking."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class ComposeError(Exception):
    """Raised when a file is not a valid Docker Compose file."""


class LineLoader(yaml.SafeLoader):
    """YAML loader that captures line numbers for mapping keys.

    Subclasses ``yaml.SafeLoader``, so it inherits the safe constructor set
    and CANNOT instantiate arbitrary Python objects. Static analyzers that
    flag ``yaml.load(...)`` calls below as unsafe are false positives — the
    only override here is the mapping constructor, which records line
    numbers for string keys and otherwise delegates to the safe loader.
    """


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


LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
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


def _collect_lines(data: Any, prefix: str = "") -> dict[str, int]:
    """Collect line numbers into a flat dot-notation map.

    Iterative traversal with an explicit work stack so pathologically-
    nested YAML can't exhaust the interpreter's recursion limit.
    """
    lines: dict[str, int] = {}
    stack: list[tuple[Any, str]] = [(data, prefix)]
    while stack:
        current, current_prefix = stack.pop()
        if isinstance(current, dict):
            line_map = current.get("__lines__", {})
            for key, value in current.items():
                if key == "__lines__":
                    continue
                full_key = f"{current_prefix}.{key}" if current_prefix else key
                if key in line_map:
                    lines[full_key] = line_map[key]
                stack.append((value, full_key))
        elif isinstance(current, list):
            for i, item in enumerate(current):
                stack.append((item, f"{current_prefix}[{i}]"))
    return lines


def _validate_compose(data: Any) -> dict[str, Any]:
    """Validate that parsed YAML is a Docker Compose file."""
    if not isinstance(data, dict):
        raise ComposeError(
            "Not a valid Compose file: expected a YAML mapping at the top level"
        )

    if "services" not in data:
        raise ComposeError("Not a valid Compose file: missing 'services' key")

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
    try:
        raw = yaml.load(  # noqa: S506  # nosec B506 - LineLoader extends SafeLoader
            content, Loader=LineLoader
        )
    except yaml.YAMLError as e:
        raise ComposeError(f"Invalid YAML: {e}") from e

    if raw is None:
        raise ComposeError("Not a valid Compose file: file is empty")

    _validate_compose(raw)

    lines = _collect_lines(raw)
    data = _strip_lines(raw)

    return data, lines
