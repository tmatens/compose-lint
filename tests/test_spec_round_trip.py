"""The Compose spec's keys round-trip through ``docs/compose-keys.md``.

Three Compose additions that carry a container or a grant (``use_api_socket``,
lifecycle hooks, ``jobs:``) were found by reading the spec by hand, months
after they shipped, because the parser accepts unknown keys by design and a
new one is silent rather than an error. This test holds the key table in
``docs/compose-keys.md`` to a vendored copy of the spec's schema
(``tests/data/compose-spec/``, refreshed by ``compose-spec-bump.yml``), so a
key the spec adds fails here until the page says what compose-lint does with
it, and every slot the schema shapes as a container is either traversed or
has an issue that will make it so (issue #1187).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "tests" / "data" / "compose-spec" / "compose-spec.json"
SOURCE = ROOT / "tests" / "data" / "compose-spec" / "SOURCE"
PAGE = ROOT / "docs" / "compose-keys.md"

DISPOSITIONS = (
    "graded",
    "engine",
    "traversed",
    "not traversed",
    "parse-only",
    "not graded",
)
_ROW = re.compile(r"^\| `([a-z_]+)` \| ([a-z, -]+) \| (.+) \|$")


def _schema() -> dict[str, Any]:
    with SCHEMA.open(encoding="utf-8") as fh:
        loaded: dict[str, Any] = json.load(fh)
    return loaded


def _definitions(schema: dict[str, Any]) -> dict[str, Any]:
    defs: dict[str, Any] = schema["$defs"]
    return defs


def _properties(
    defs: dict[str, Any], definition: dict[str, Any], seen: tuple[str, ...] = ()
) -> set[str]:
    """Every property a definition carries, following ``allOf`` references."""
    keys = set(definition.get("properties", {}))
    for part in definition.get("allOf", []):
        ref = part.get("$ref")
        if ref is None:
            keys |= _properties(defs, part, seen)
            continue
        name = ref.rsplit("/", 1)[-1]
        if name not in seen:
            keys |= _properties(defs, defs[name], (*seen, name))
    return keys


def _resolves_to(
    defs: dict[str, Any], node: Any, target: str, seen: tuple[str, ...] = ()
) -> bool:
    """Whether a schema node reaches ``$defs/<target>`` through references.

    Follows ``$ref``, ``allOf``/``oneOf``/``anyOf``, ``items`` and
    ``patternProperties``: the shapes the spec uses to say "a mapping of X",
    "a list of X" and "X plus these keys".
    """
    if not isinstance(node, dict):
        return False
    ref = node.get("$ref")
    if ref is not None:
        name = ref.rsplit("/", 1)[-1]
        if name == target:
            return True
        if name in seen or name not in defs:
            return False
        return _resolves_to(defs, defs[name], target, (*seen, name))
    for key in ("allOf", "oneOf", "anyOf"):
        if any(_resolves_to(defs, part, target, seen) for part in node.get(key, [])):
            return True
    if "items" in node and _resolves_to(defs, node["items"], target, seen):
        return True
    patterned = node.get("patternProperties", {}).values()
    return any(_resolves_to(defs, sub, target, seen) for sub in patterned)


def _spec_keys() -> dict[str, set[str]]:
    """Every key the spec defines, mapped to the places it may appear."""
    schema = _schema()
    defs = _definitions(schema)
    service = _properties(defs, defs["service"])
    job = _properties(defs, defs["job"])
    places: dict[str, set[str]] = {key: {"top-level"} for key in schema["properties"]}
    for key in service | job:
        where = set()
        if key in service:
            where.add("service")
        if key in job:
            where.add("job")
        places[key] = places.get(key, set()) | where
    return places


def _container_slots() -> dict[str, set[str]]:
    """Keys whose value is one or more containers, by place.

    A slot is any top-level or service property that resolves to
    ``container_spec`` (a container) or ``service_hook`` (a command run inside
    one). These are the keys the engine must traverse (ADR-040).
    """
    schema = _schema()
    defs = _definitions(schema)
    slots: dict[str, set[str]] = {}
    for key, node in schema["properties"].items():
        if _resolves_to(defs, node, "container_spec"):
            slots.setdefault(key, set()).add("top-level")
    service_props: dict[str, Any] = {}

    def collect(definition: dict[str, Any], seen: tuple[str, ...] = ()) -> None:
        service_props.update(definition.get("properties", {}))
        for part in definition.get("allOf", []):
            ref = part.get("$ref")
            if ref is None:
                collect(part, seen)
                continue
            name = ref.rsplit("/", 1)[-1]
            if name not in seen:
                collect(defs[name], (*seen, name))

    collect(defs["service"])
    for key, node in service_props.items():
        if _resolves_to(defs, node, "container_spec") or _resolves_to(
            defs, node, "service_hook"
        ):
            slots.setdefault(key, set()).add("service")
    return slots


def _page_rows() -> dict[tuple[str, str], str]:
    """``(key, where) -> disposition`` for every row of the page's table."""
    rows: dict[tuple[str, str], str] = {}
    for line in PAGE.read_text(encoding="utf-8").splitlines():
        match = _ROW.match(line)
        if match is None:
            continue
        key, where, disposition = match.groups()
        assert (key, where) not in rows, f"{key} ({where}) listed twice"
        rows[(key, where)] = disposition
    assert rows, "no table rows found in docs/compose-keys.md"
    return rows


def _page_places() -> dict[str, set[str]]:
    places: dict[str, set[str]] = {}
    for key, where in _page_rows():
        places[key] = places.get(key, set()) | {w.strip() for w in where.split(",")}
    return places


class TestVendoredSchema:
    def test_is_the_compose_specification(self) -> None:
        schema = _schema()
        assert schema["title"] == "Compose Specification"
        assert "container_spec" in _definitions(schema)

    def test_source_records_the_upstream_commit(self) -> None:
        text = SOURCE.read_text(encoding="utf-8")
        commit = re.search(r"^commit: ([0-9a-f]{40})$", text, re.M)
        assert commit is not None, "SOURCE must name the upstream commit"
        assert commit.group(1) in text.split("url:", 1)[1].splitlines()[0]
        assert "compose-spec/compose-spec" in text
        assert "LICENSE-compose-spec.md" in text
        assert (ROOT / "LICENSE-compose-spec.md").is_file()


class TestKeyTable:
    def test_every_spec_key_has_a_row_and_nothing_else_does(self) -> None:
        spec = _spec_keys()
        page = _page_places()
        missing = sorted(set(spec) - set(page))
        extra = sorted(set(page) - set(spec))
        assert not missing, (
            f"the spec defines {missing} and docs/compose-keys.md does not say what "
            "compose-lint does with them. Add a row per key; a key that holds "
            "containers is 'traversed' or 'not traversed (#issue)'."
        )
        assert not extra, (
            f"docs/compose-keys.md lists {extra}, which the spec does not define"
        )

    def test_each_row_names_where_the_spec_allows_the_key(self) -> None:
        spec = _spec_keys()
        for key, places in _page_places().items():
            assert places == spec[key], (
                f"{key}: page says {sorted(places)}, spec says {sorted(spec[key])}"
            )

    @pytest.mark.parametrize("disposition", sorted({d for d in _page_rows().values()}))
    def test_every_disposition_starts_with_a_known_word(self, disposition: str) -> None:
        assert disposition.startswith(DISPOSITIONS), disposition

    def test_graded_rows_name_registered_rules(self) -> None:
        from compose_lint.rules import get_registered_rules

        registered = {cls().metadata.id for cls in get_registered_rules()}
        for (key, _), disposition in _page_rows().items():
            if not disposition.startswith("graded"):
                continue
            named = set(re.findall(r"CL-\d{4}", disposition))
            assert named, f"{key}: 'graded' must list the rules"
            assert named <= registered, (
                f"{key} names unregistered rules {sorted(named - registered)}"
            )

    def test_not_graded_and_not_traversed_rows_cite_an_issue(self) -> None:
        for (key, _), disposition in _page_rows().items():
            if disposition.startswith(("not graded", "not traversed")):
                assert re.search(r"#\d+", disposition), (
                    f"{key}: cite the issue that records it"
                )


class TestContainerSlots:
    def test_the_resolver_finds_the_known_slots(self) -> None:
        # Pinned so a schema refresh that adds a slot fails here with its name,
        # and so a resolver regression cannot pass by finding nothing.
        assert _container_slots() == {
            "services": {"top-level"},
            "jobs": {"top-level"},
            "pre_start": {"service"},
            "post_start": {"service"},
            "pre_stop": {"service"},
        }

    def test_every_container_slot_is_traversed_or_has_an_issue(self) -> None:
        rows = _page_rows()
        for key, places in _container_slots().items():
            for where in places:
                row = next(
                    (d for (k, w), d in rows.items() if k == key and where in w), None
                )
                assert row is not None, f"{key} ({where}) has no row"
                assert row.startswith(("traversed", "not traversed (#")), (
                    f"{key} holds containers; its row must read 'traversed' or "
                    f"'not traversed (#issue)', not {row!r}"
                )
