"""Tests for the Compose file parser."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from compose_lint.parser import (
    ComposeError,
    ComposeNotApplicableError,
    _collect_lines,
    _strip_lines,
    load_compose,
    loads,
)

FIXTURES = Path(__file__).parent / "compose_files"


class TestLoads:
    """Tests for the in-memory string parser (parity with load_compose)."""

    def test_parses_valid_string(self) -> None:
        data, lines = loads("services:\n  web:\n    image: nginx:1.27\n")
        assert data["services"]["web"]["image"] == "nginx:1.27"
        # Line capture works the same as the path-based loader.
        assert lines["services.web"] == 2

    def test_raises_on_invalid_yaml(self) -> None:
        with pytest.raises(ComposeError, match="Invalid YAML"):
            loads("services: [\n")

    def test_raises_on_invalid_compose(self) -> None:
        # The H1 corruption shape: a service with a null body.
        with pytest.raises(ComposeError, match="service 'web' must be a mapping"):
            loads("services:\n  web:\n")

    def test_raises_on_empty(self) -> None:
        with pytest.raises(ComposeError, match="file is empty"):
            loads("")


class TestDuplicateKeys:
    """Duplicate mapping keys are rejected, matching Docker (#277 P2)."""

    def test_duplicate_key_in_service_rejected(self) -> None:
        # PyYAML let the last value win; Docker rejects the file outright.
        with pytest.raises(ComposeError, match="duplicate key 'privileged'"):
            loads(
                "services:\n"
                "  web:\n"
                "    image: nginx\n"
                "    privileged: false\n"
                "    privileged: true\n"
            )

    def test_duplicate_service_name_rejected(self) -> None:
        with pytest.raises(ComposeError, match="duplicate key 'web'"):
            loads("services:\n  web:\n    image: a\n  web:\n    image: b\n")

    def test_merge_key_override_is_not_a_duplicate(self) -> None:
        # A merge key legitimately reintroduces an overridden key; the explicit
        # value wins and the file stays valid.
        data, _lines = loads(
            "x-base: &base\n"
            "  image: nginx\n"
            '  restart: "no"\n'
            "services:\n"
            "  web:\n"
            "    <<: *base\n"
            "    restart: always\n"
        )
        assert data["services"]["web"]["restart"] == "always"
        assert data["services"]["web"]["image"] == "nginx"


class TestOverrideTags:
    """Compose override-file tags (`!reset` / `!override`) parse, not crash."""

    def test_override_sequence(self) -> None:
        # Issue #277 B1: !override is valid Compose syntax; the value is the list.
        data, _lines = loads(
            'services:\n  app:\n    image: nginx\n    ports: !override ["8443:443"]\n'
        )
        assert data["services"]["app"]["ports"] == ["8443:443"]

    def test_reset_scalar_is_none(self) -> None:
        data, _lines = loads(
            "services:\n  app:\n    image: nginx\n    ports: !reset null\n"
        )
        assert data["services"]["app"]["ports"] is None

    def test_override_scalar_keeps_implicit_type(self) -> None:
        # The override tag is stripped, so the scalar resolves to its plain type.
        data, _lines = loads(
            "services:\n  app:\n    image: nginx\n    shm_size: !override 8080\n"
        )
        assert data["services"]["app"]["shm_size"] == 8080

    def test_override_mapping_keeps_line_tracking(self) -> None:
        data, lines = loads(
            "services:\n"
            "  app:\n"
            "    image: nginx\n"
            "    environment: !override\n"
            "      FOO: bar\n"
        )
        assert data["services"]["app"]["environment"] == {"FOO": "bar"}
        assert lines["services.app.environment.FOO"] == 5


class TestScalarResolvers:
    """LineLoader avoids the YAML 1.1 sexagesimal and timestamp traps (#277 F1)."""

    def test_sexagesimal_ports_stay_strings(self) -> None:
        # `22:22` parsed as the base-60 int 1342 under YAML 1.1, hiding the colon
        # from CL-0005. Both sides <= 59 must now stay a string.
        data, _lines = loads(
            "services:\n"
            "  a:\n"
            "    image: nginx\n"
            "    ports:\n"
            "      - 22:22\n"
            "      - 25:25\n"
            "      - 53:53\n"
        )
        ports = data["services"]["a"]["ports"]
        assert ports == ["22:22", "25:25", "53:53"]
        assert all(isinstance(p, str) for p in ports)

    def test_plain_ints_and_floats_still_typed(self) -> None:
        data, _lines = loads(
            "services:\n  a:\n    image: nginx\n    cpu_count: 8080\n    ratio: 3.14\n"
        )
        svc = data["services"]["a"]
        assert svc["cpu_count"] == 8080
        assert svc["ratio"] == 3.14

    def test_booleans_keep_yaml_1_1_spelling(self) -> None:
        # Docker coerces yes/no/on/off to booleans for boolean-typed fields, so
        # these must stay bool or CL-0002/CL-0007 would miss `privileged: yes`.
        data, _lines = loads(
            "services:\n"
            "  a:\n"
            "    image: nginx\n"
            "    privileged: yes\n"
            "    read_only: off\n"
        )
        svc = data["services"]["a"]
        assert svc["privileged"] is True
        assert svc["read_only"] is False

    def test_bare_timestamp_stays_string(self) -> None:
        # A bare date became a datetime.date under YAML 1.1, which is not
        # JSON-serializable and breaks string-oriented rules.
        data, _lines = loads(
            "services:\n  a:\n    image: nginx\n    labels:\n      built: 2024-01-01\n"
        )
        built = data["services"]["a"]["labels"]["built"]
        assert built == "2024-01-01"
        assert isinstance(built, str)


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

    def test_sequence_merge_keys(self) -> None:
        # Compose accepts the YAML sequence-merge form `<<: [*a, *b]` to
        # combine multiple anchored mappings into one service. Real-world
        # corpus files use this (e.g. CVAT) — this fixture asserts both
        # anchored mappings are merged in and that line attribution still
        # falls inside the service block.
        data, lines = load_compose(FIXTURES / "valid_anchors_seq_merge.yml")
        web = data["services"]["web"]
        assert web["restart"] == "unless-stopped"
        assert web["read_only"] is True
        assert web["security_opt"] == ["no-new-privileges:true"]
        assert web["image"] == "nginx:1.27-alpine"
        assert lines["services.web"] > lines["services"]

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

    def test_non_utf8_file_raises_compose_error(self, tmp_path: Path) -> None:
        # Issue #277 B2: a latin-1 file raises UnicodeDecodeError (a ValueError),
        # which the OSError handler does not catch. Left uncaught it aborts a whole
        # directory sweep; it must surface as a per-file ComposeError instead.
        path = tmp_path / "latin1.yml"
        path.write_bytes("services:\n  app:\n    image: caf\xe9\n".encode("latin-1"))
        with pytest.raises(ComposeError, match="Invalid encoding"):
            load_compose(path)

    def test_empty_file(self) -> None:
        with pytest.raises(ComposeError, match="file is empty"):
            load_compose(FIXTURES / "invalid_empty.yml")

    def test_no_services_key_unrecognised_shape(self) -> None:
        # Top-level mapping with neither `services:`, fragment-shaped keys,
        # nor v1-shaped service mappings: still a hard error per ADR-013.
        with pytest.raises(ComposeError, match="missing 'services' key"):
            load_compose(FIXTURES / "invalid_no_services.yml")
        # Specifically NOT the not-applicable subtype.
        with pytest.raises(ComposeError) as excinfo:
            load_compose(FIXTURES / "invalid_no_services.yml")
        assert not isinstance(excinfo.value, ComposeNotApplicableError)

    def test_fragment_skipped_as_not_applicable(self) -> None:
        # ADR-013: a file containing only top-level structural keys
        # (volumes/networks/configs/secrets/x-*) is a fragment for
        # `extends:`/`-f` overlay use; the linter doesn't apply.
        with pytest.raises(ComposeNotApplicableError, match="Compose fragment"):
            load_compose(FIXTURES / "fragment_volumes_only.yml")

    def test_legacy_v1_skipped_as_not_applicable(self) -> None:
        # ADR-013: services declared at the top level (no `services:` wrapper)
        # is the v1 schema. Docker retired Compose v1 in 2023; we skip rather
        # than fail so directory sweeps don't drop downstream files.
        with pytest.raises(ComposeNotApplicableError, match="Compose v1"):
            load_compose(FIXTURES / "legacy_v1_compose.yml")

    def test_not_applicable_is_a_compose_error_subtype(self) -> None:
        # Callers that catch ComposeError still see fragment/v1 errors;
        # callers that want to special-case "skip" can catch the subtype.
        with pytest.raises(ComposeError):
            load_compose(FIXTURES / "fragment_volumes_only.yml")

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

    def test_collect_lines_bounds_chained_alias_blowup(self) -> None:
        # Regression for issue #154: ClusterFuzzLite found a sub-1KB Compose
        # file where chained YAML aliases fanned out _collect_lines into
        # O(branching^depth) traversal, growing memory past 3GB and OOMing
        # the linter. Without the id() memoization the parsed graph below
        # expands to >11M path entries (~1.4GB); with it, work stays linear
        # in the number of unique nodes.
        import time

        import yaml

        from compose_lint.parser import LineLoader

        content = """services:
  s: {image: foo}
a: &a {x: 1}
b: &b {p: *a, q: *a, r: *a, s: *a, t: *a, u: *a, v: *a, w: *a, x: *a}
c: &c {p: *b, q: *b, r: *b, s: *b, t: *b, u: *b, v: *b, w: *b, x: *b}
d: &d {p: *c, q: *c, r: *c, s: *c, t: *c, u: *c, v: *c, w: *c, x: *c}
e: &e {p: *d, q: *d, r: *d, s: *d, t: *d, u: *d, v: *d, w: *d, x: *d}
f: &f {p: *e, q: *e, r: *e, s: *e, t: *e, u: *e, v: *e, w: *e, x: *e}
g: &g {p: *f, q: *f, r: *f, s: *f, t: *f, u: *f, v: *f, w: *f, x: *f}
h: {p: *g, q: *g, r: *g, s: *g, t: *g, u: *g, v: *g, w: *g, x: *g}
"""
        raw = yaml.load(content, Loader=LineLoader)  # noqa: S506
        start = time.perf_counter()
        result = _collect_lines(raw)
        elapsed = time.perf_counter() - start
        # Pre-fix: ~35s and >11M entries on a typical CI runner.
        assert elapsed < 1.0
        assert len(result) < 1000
        # The legitimate `services.s.image` lookup still resolves.
        assert "services.s" in result
