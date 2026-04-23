"""Tests for the Compose file parser."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from compose_lint.parser import (
    ComposeError,
    _collect_lines,
    _strip_lines,
    load_compose,
)

FIXTURES = Path(__file__).parent / "compose_files"


class TestLoadCompose:
    """Tests for load_compose function."""

    def test_basic_valid_file(self) -> None:
        data, lines = load_compose(FIXTURES / "valid_basic.yml")
        assert "services" in data
        assert "web" in data["services"]
        assert "db" in data["services"]
        assert (
            data["services"]["web"]["image"]
            == "nginx:1.27-alpine@sha256:a1234567890abcdef"
        )

    def test_returns_plain_dicts(self) -> None:
        data, _lines = load_compose(FIXTURES / "valid_basic.yml")
        assert isinstance(data, dict)
        assert isinstance(data["services"], dict)
        assert isinstance(data["services"]["web"], dict)

    def test_no_lines_metadata_in_data(self) -> None:
        data, _lines = load_compose(FIXTURES / "valid_basic.yml")
        assert "__lines__" not in data
        assert "__lines__" not in data["services"]
        assert "__lines__" not in data["services"]["web"]

    def test_line_numbers_present(self) -> None:
        _data, lines = load_compose(FIXTURES / "valid_basic.yml")
        assert "services" in lines
        assert "services.web" in lines
        assert "services.db" in lines
        assert lines["services"] == 1
        assert lines["services.web"] > 0
        assert lines["services.db"] > lines["services.web"]

    def test_anchors_and_merge_keys(self) -> None:
        data, _lines = load_compose(FIXTURES / "valid_anchors.yml")
        web = data["services"]["web"]
        assert web["restart"] == "unless-stopped"
        assert web["image"] == "nginx:1.27-alpine"

    def test_v2_with_version_key(self) -> None:
        data, _lines = load_compose(FIXTURES / "valid_v2.yml")
        assert "services" in data
        assert "web" in data["services"]

    def test_env_interpolation_preserved(self) -> None:
        data, _lines = load_compose(FIXTURES / "valid_env_interpolation.yml")
        app = data["services"]["app"]
        assert "${APP_VERSION:-latest}" in app["image"]

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_compose(FIXTURES / "nonexistent.yml")

    def test_empty_file(self) -> None:
        with pytest.raises(ComposeError, match="file is empty"):
            load_compose(FIXTURES / "invalid_empty.yml")

    def test_no_services_key(self) -> None:
        with pytest.raises(ComposeError, match="missing 'services' key"):
            load_compose(FIXTURES / "invalid_no_services.yml")

    def test_services_not_mapping(self) -> None:
        with pytest.raises(ComposeError, match="'services' must be a mapping"):
            load_compose(FIXTURES / "invalid_services_not_mapping.yml")

    def test_service_not_mapping(self) -> None:
        with pytest.raises(ComposeError, match="service 'web' must be a mapping"):
            load_compose(FIXTURES / "invalid_service_not_mapping.yml")

    def test_invalid_yaml(self) -> None:
        with pytest.raises(ComposeError, match="Invalid YAML"):
            load_compose(FIXTURES / "invalid_yaml.yml")

    def test_unhashable_complex_key(self) -> None:
        # Regression: ClusterFuzzLite found that YAML's `? <mapping>` complex-key
        # syntax raised a raw TypeError from parser._construct_mapping instead
        # of a ComposeError. The parser now rejects unhashable keys up front.
        with pytest.raises(ComposeError, match="unhashable key"):
            load_compose(FIXTURES / "invalid_complex_key.yml")

    def test_deeply_nested_yaml_raises_compose_error(self, tmp_path: Path) -> None:
        # Regression: ClusterFuzzLite found that deeply-nested flow sequences
        # (`[[[[...]]]]`) exhaust PyYAML's recursive composer and raise
        # RecursionError, which is a RuntimeError and bypassed the
        # `except yaml.YAMLError` wrapper. load_compose now catches it.
        depth = sys.getrecursionlimit() * 2
        path = tmp_path / "deeply_nested.yml"
        path.write_text("[" * depth + "]" * depth, encoding="utf-8")
        with pytest.raises(ComposeError, match="too deeply nested"):
            load_compose(path)


class TestDeepNestingTraversal:
    """Regression for ClusterFuzzLite-found RecursionError in _collect_lines.

    The parser's post-YAML traversals used to recurse one Python frame per
    nesting level. An input deeper than sys.getrecursionlimit() crashed the
    tool with an uncaught RecursionError instead of either linting or
    rejecting the file. These tests construct dicts deeper than the default
    recursion limit, bypassing YAML parsing (which has its own independent
    limit) to exercise the traversal functions directly.
    """

    @staticmethod
    def _build_deep_chain(depth: int) -> dict[str, Any]:
        node: Any = "leaf"
        for i in range(depth):
            node = {"a": node, "__lines__": {"a": i + 1}}
        return node

    def test_collect_lines_handles_depth_above_recursion_limit(self) -> None:
        depth = sys.getrecursionlimit() * 2
        node = self._build_deep_chain(depth)
        result = _collect_lines(node)
        # One entry per level (all keyed "a"-chained via dot notation).
        assert len(result) == depth

    def test_strip_lines_handles_depth_above_recursion_limit(self) -> None:
        depth = sys.getrecursionlimit() * 2
        node = self._build_deep_chain(depth)
        result = _strip_lines(node)
        # Walk iteratively (not recursively) to verify every level was stripped.
        walk: Any = result
        for _ in range(depth):
            assert isinstance(walk, dict)
            assert "__lines__" not in walk
            walk = walk["a"]
        assert walk == "leaf"

    def test_strip_lines_dedupes_shared_subtrees(self) -> None:
        # YAML anchors produce the same Python dict reachable from multiple
        # parents. The iterative impl memoizes by id() so shared subtrees
        # are processed once, keeping work linear in the underlying graph.
        shared = {"image": "nginx", "__lines__": {"image": 3}}
        root = {
            "services": {
                "web": shared,
                "api": shared,
                "__lines__": {"web": 2, "api": 4},
            },
            "__lines__": {"services": 1},
        }
        stripped = _strip_lines(root)
        # Same stripped dict returned for both aliases.
        assert stripped["services"]["web"] is stripped["services"]["api"]
        assert "__lines__" not in stripped["services"]["web"]
