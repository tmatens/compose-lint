"""The merge's cost stays proportional to the documents, not to what aliases expand to.

Three places in the merge did work in the size of a value rather than of the
file that wrote it:

- a long-form port entry was keyed with ``str()`` of each field, so a
  ``host_ip`` written as a doubling alias chain was rendered in full: a few
  hundred bytes of YAML under a one-line overlay ran out of memory;
- the append-style dedupe compared each entry with ``==`` against every one
  kept so far, which walks two distinct alias chains of the same shape
  node by node: 1.6 KB of YAML took most of a minute;
- re-keying a subtree scanned the side's whole line map, once per item of a
  merged list, so a long ``dns:`` under a one-line overlay was quadratic.

The tests assert the structure that bounds each cost rather than a wall-clock
time, so a regression fails here instead of timing out a runner.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import TYPE_CHECKING, Any

from compose_lint._merge import (
    _DEDUPE_NODES,
    Document,
    _dedupe_key,
    _port_key,
    _Recorder,
    _Side,
    merge_documents,
)
from compose_lint.parser import loads

if TYPE_CHECKING:
    from pathlib import Path


def _chain(depth: int, leaf: str = "x") -> list[Any]:
    """A doubling alias chain as the parser builds it: one list, shared twice."""
    node: list[Any] = [leaf, leaf]
    for _ in range(depth):
        node = [node, node]
    return node


def _chain_yaml(name: str, depth: int) -> list[str]:
    lines = [f"  {name}0: &{name}0 [x, x]"]
    lines += [
        f"  {name}{k}: &{name}{k} [*{name}{k - 1}, *{name}{k - 1}]"
        for k in range(1, depth + 1)
    ]
    return lines


class TestPortKey:
    def test_scalar_fields_key_as_before(self) -> None:
        assert _port_key({"target": 80, "published": 8080}) == "|8080|80|tcp"
        assert _port_key({"target": 80, "host_ip": "127.0.0.1"}) == (
            "127.0.0.1||80|tcp"
        )
        assert _port_key("127.0.0.1:8080:80/udp") == "127.0.0.1|8080|80|udp"

    def test_a_non_scalar_field_has_no_key(self) -> None:
        """Compose rejects it (`host_ip must be a string`); rendering it was the
        cost, so it merges unkeyed instead."""
        assert _port_key({"target": 80, "host_ip": _chain(40)}) is None
        assert _port_key({"target": {"a": 1}}) is None
        assert _port_key({"target": 80, "published": [8080]}) is None

    def test_an_alias_chain_host_ip_under_an_overlay_is_linted(
        self, tmp_path: Path
    ) -> None:
        """The overlay route: any base with a sibling `compose.override.yml`.
        Depth 40 would be a terabyte of text if any field were rendered."""
        base = ["x-c:", *_chain_yaml("a", 40)]
        base += [
            "services:",
            "  web:",
            "    image: nginx:1.27",
            "    ports:",
            "      - target: 80",
            "        host_ip: *a40",
        ]
        (tmp_path / "compose.yml").write_text("\n".join(base) + "\n")
        (tmp_path / "compose.override.yml").write_text(
            "services:\n  web:\n    ports:\n      - target: 81\n"
        )
        result = subprocess.run(  # noqa: S603 - fixed argv
            [sys.executable, "-m", "compose_lint", "--format", "json"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        doc = json.loads(result.stdout)
        assert doc["errors"] == []
        assert result.returncode in (0, 1)


class TestDedupeKey:
    def test_equal_keys_exactly_where_equality_holds(self) -> None:
        pairs = [
            ("a", "a", True),
            ("a", "b", False),
            (1, True, True),
            (1, 1.0, True),
            (None, "", False),
            (["a", "b"], ["a", "b"], True),
            (["a", "b"], ["b", "a"], False),
            ({"x": 1, "y": [2]}, {"y": [2], "x": 1}, True),
            ({"x": 1}, {"x": 2}, False),
            (["a"], "a", False),
            ({"a": 1}, [("a", 1)], False),
        ]
        for left, right, equal in pairs:
            assert (left == right) is equal, (left, right)
            assert (_dedupe_key(left) == _dedupe_key(right)) is equal, (left, right)

    def test_distinct_equal_chains_are_not_walked(self) -> None:
        """Two chains of the same shape, from two different anchors. `==` walks
        2**depth nodes to compare them; the key stops at the node budget."""
        left, right = _chain(60), _chain(60)
        assert left is not right
        assert _dedupe_key(left) != _dedupe_key(right)

    def test_one_large_entry_repeated_still_deduplicates(self) -> None:
        shared = _chain(60)
        assert _dedupe_key(shared) == _dedupe_key(shared)

    def test_the_budget_is_the_whole_entry(self) -> None:
        """Small entries compare by value up to the bound, and not past it."""
        small = ["x"] * (_DEDUPE_NODES - 2)
        assert _dedupe_key(list(small)) == _dedupe_key(list(small))
        large = ["x"] * _DEDUPE_NODES
        assert _dedupe_key(list(large)) != _dedupe_key(list(large))

    def test_the_merge_still_deduplicates_by_value(self) -> None:
        base = Document(
            "a.yml", {"services": {"w": {"dns": ["1.1.1.1", "8.8.8.8"]}}}, {}
        )
        over = Document(
            "b.yml", {"services": {"w": {"dns": ["8.8.8.8", "9.9.9.9"]}}}, {}
        )
        merged = merge_documents([base, over])
        assert merged.data["services"]["w"]["dns"] == [
            "1.1.1.1",
            "8.8.8.8",
            "9.9.9.9",
        ]

    def test_distinct_equal_chains_in_an_extends_merge(self) -> None:
        text = "\n".join(
            [
                "x-c:",
                *_chain_yaml("a", 60),
                *_chain_yaml("b", 60),
                "services:",
                "  base:",
                "    image: nginx:1.27",
                "    dns: [*a60]",
                "  child:",
                "    extends: base",
                "    dns: [*b60]",
            ]
        )
        data, _ = loads(text + "\n")
        assert len(data["services"]["child"]["dns"]) == 2


class TestSubtreeRecording:
    def _document(self) -> Document:
        lines = {
            "services": 1,
            "services.web": 2,
            "services.web.dns": 3,
            "services.web.dns[0]": 4,
            "services.web.dns[1]": 5,
            "services.web.dns[10]": 6,
            "services.web.dns[1].x": 7,
            "services.web.dns_search": 8,
            "services.webx": 9,
            "services.web.dns.nested": 10,
        }
        return Document("a.yml", {}, lines)

    def test_only_the_subtree_is_copied(self) -> None:
        """Siblings that share a prefix (`dns[10]` under `dns[1]`, `dns_search`
        under `dns`, `webx` under `web`) are not descendants."""
        doc = self._document()
        rec = _Recorder()
        rec.take_subtree("out", _Side(None, doc, "services.web.dns[1]"))
        assert dict(rec.lines) == {"out": 5, "out.x": 7}

        rec = _Recorder()
        rec.take_subtree("out", _Side(None, doc, "services.web.dns"))
        assert list(rec.lines) == [
            "out",
            "out[0]",
            "out[1]",
            "out[10]",
            "out[1].x",
            "out.nested",
        ]

        rec = _Recorder()
        rec.take_subtree("svc", _Side(None, doc, "services.web"))
        assert "svc.dns_search" in rec.lines
        assert not any(key.startswith("svcx") for key in rec.lines)

    def test_the_line_map_is_indexed_once_per_merge(self) -> None:
        doc = self._document()
        rec = _Recorder()
        for i in range(3):
            rec.take_subtree(f"o{i}", _Side(None, doc, f"services.web.dns[{i}]"))
        assert len(rec._indexes) == 1

    def test_lines_and_sources_survive_a_long_merged_list(self) -> None:
        entries = [f"d{i}" for i in range(2000)]
        base_lines = {f"services.w.dns[{i}]": 10 + i for i in range(2000)}
        base = Document("a.yml", {"services": {"w": {"dns": entries}}}, base_lines)
        over = Document(
            "b.yml",
            {"services": {"w": {"dns": ["z"]}}},
            {"services.w.dns[0]": 3},
        )
        merged = merge_documents([base, over])
        assert merged.lines["services.w.dns[1999]"] == 2009
        assert merged.sources["services.w.dns[1999]"] == "a.yml"
        assert merged.lines["services.w.dns[2000]"] == 3
        assert merged.sources["services.w.dns[2000]"] == "b.yml"
