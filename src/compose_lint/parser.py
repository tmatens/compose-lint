"""YAML parser for Docker Compose files with line number tracking."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Union

import yaml


class ComposeError(Exception):
    """Raised when a file is not a valid Docker Compose file."""


class LineLoader(yaml.SafeLoader):
    """YAML loader that captures line numbers for mapping keys."""


def _construct_mapping(loader: LineLoader, node: yaml.MappingNode) -> dict[str, Any]:
    loader.flatten_mapping(node)
    pairs = loader.construct_pairs(node)
    mapping: dict[str, Any] = {}
    line_map: dict[str, int] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        value = loader.construct_object(value_node)
        if isinstance(key, str):
            line_map[key] = key_node.start_mark.line + 1
        mapping[key] = value
    mapping["__lines__"] = line_map
    return mapping


LineLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,  # type: ignore[arg-type]
)


def _strip_lines(data: Any) -> Any:
    """Recursively remove __lines__ metadata from parsed data."""
    if isinstance(data, dict):
        return {k: _strip_lines(v) for k, v in data.items() if k != "__lines__"}
    if isinstance(data, list):
        return [_strip_lines(item) for item in data]
    return data


def _collect_lines(data: Any, prefix: str = "") -> dict[str, int]:
    """Recursively collect line numbers into a flat dot-notation map."""
    lines: dict[str, int] = {}
    if isinstance(data, dict):
        line_map = data.get("__lines__", {})
        for key, value in data.items():
            if key == "__lines__":
                continue
            full_key = f"{prefix}.{key}" if prefix else key
            if key in line_map:
                lines[full_key] = line_map[key]
            lines.update(_collect_lines(value, full_key))
    if isinstance(data, list):
        for i, item in enumerate(data):
            lines.update(_collect_lines(item, f"{prefix}[{i}]"))
    return lines


def _validate_compose(data: Any) -> dict[str, Any]:
    """Validate that parsed YAML is a Docker Compose file."""
    if not isinstance(data, dict):
        raise ComposeError(
            "Not a valid Compose file: expected a YAML mapping at the top level"
        )

    if "services" not in data:
        raise ComposeError(
            "Not a valid Compose file: missing 'services' key"
        )

    services = data["services"]
    if not isinstance(services, dict):
        raise ComposeError(
            "Not a valid Compose file: 'services' must be a mapping"
        )

    for name, config in services.items():
        if name == "__lines__":
            continue
        if not isinstance(config, dict):
            raise ComposeError(
                f"Not a valid Compose file: service '{name}' must be a mapping"
            )

    return data


def load_compose(
    path: Union[str, Path],
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

    try:
        raw = yaml.load(content, Loader=LineLoader)  # noqa: S506
    except yaml.YAMLError as e:
        raise ComposeError(f"Invalid YAML: {e}") from e

    if raw is None:
        raise ComposeError("Not a valid Compose file: file is empty")

    _validate_compose(raw)

    lines = _collect_lines(raw)
    data = _strip_lines(raw)

    return data, lines
