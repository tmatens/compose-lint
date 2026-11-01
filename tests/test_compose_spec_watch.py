"""Tests for scripts/compose_spec_watch.py (issue #1187).

The script reduces the Compose spec's JSON schema to key names and container
slots and reports changes against ``scripts/compose_spec_keys.json``. These
tests drive it with small inline schemas, one per way a schema can add a key
or nest a container, because a resolver that misses a shape reports nothing,
which is exactly the silence the script exists to end. No test touches the
network.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import re
import sys
from typing import Any

import pytest

from compose_lint import _units

_PATH = (
    pathlib.Path(__file__).resolve().parent.parent / "scripts" / "compose_spec_watch.py"
)
_SPEC = importlib.util.spec_from_file_location("compose_spec_watch", _PATH)
assert _SPEC is not None and _SPEC.loader is not None
watch = importlib.util.module_from_spec(_SPEC)
sys.modules["compose_spec_watch"] = watch
_SPEC.loader.exec_module(watch)

RECORD = json.loads(watch.RECORD.read_text(encoding="utf-8"))

# Container slots the engine grades as units (ADR-040), named the way the
# record names them. Derived from the engine's own constants so a traversal
# added or removed there shows up here.
TRAVERSED = {
    "services",
    "jobs",
    f"service.{_units.PRE_START}",
    *(f"service.{kind}" for kind in _units.EXEC_HOOKS),
}

# Slots the spec defines that the engine deliberately does not traverse, with
# the reason. A slot belongs here only after triage; the watcher's issue is
# where a new one is first seen.
UNTRAVERSED = {
    "service.develop": (
        "develop.watch[].exec (Compose 2.32) is an exec hook run by "
        "`docker compose watch` on file changes. 1 entry in the 11,111-file "
        "corpus, setting only `command`; nothing gradable. Recount with the "
        "corpus (#1189)."
    ),
}


def _base() -> dict[str, Any]:
    """The smallest schema with every definition the watcher reads."""
    return {
        "title": "Compose Specification",
        "properties": {
            "services": {
                "type": "object",
                "patternProperties": {"^.+$": {"$ref": "#/$defs/service"}},
            },
            "name": {"type": "string"},
        },
        "$defs": {
            "container_spec": {
                "type": "object",
                "properties": {"image": {"type": "string"}, "user": {"type": "string"}},
            },
            "service_hook": {
                "type": "object",
                "properties": {"command": {}, "user": {"type": "string"}},
            },
            "pre_start_hook": {
                "allOf": [{"$ref": "#/$defs/container_spec"}],
                "properties": {"per_replica": {"type": "boolean"}},
            },
            "service": {
                "allOf": [{"$ref": "#/$defs/container_spec"}],
                "properties": {
                    "pre_start": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/pre_start_hook"},
                    },
                    "post_start": {
                        "type": "array",
                        "items": {"$ref": "#/$defs/service_hook"},
                    },
                    "restart": {"type": "string"},
                },
            },
            "job": {
                "allOf": [{"$ref": "#/$defs/container_spec"}],
                "properties": {"triggers": {"type": "object"}},
            },
        },
    }


def _with(mutate: Any) -> dict[str, Any]:
    schema = _base()
    mutate(schema)
    return schema


class TestShapeOfTheBase:
    def test_keys_per_place(self) -> None:
        keys = watch.shape(_base())["keys"]
        assert keys["top-level"] == ["name", "services"]
        assert keys["service"] == [
            "image",
            "post_start",
            "pre_start",
            "restart",
            "user",
        ]
        assert keys["job"] == ["image", "triggers", "user"]
        assert keys["pre_start_hook"] == ["image", "per_replica", "user"]
        assert keys["service_hook"] == ["command", "user"]

    def test_container_slots(self) -> None:
        assert watch.shape(_base())["container_slots"] == [
            "service.post_start",
            "service.pre_start",
            "services",
        ]

    def test_refuses_a_schema_that_is_not_compose(self) -> None:
        with pytest.raises(ValueError, match="not the Compose"):
            watch.shape({"title": "404: Not Found"})

    def test_refuses_a_schema_missing_a_definition(self) -> None:
        schema = _base()
        del schema["$defs"]["job"]
        with pytest.raises(ValueError, match=r"\$defs/job"):
            watch.shape(schema)

    def test_refuses_a_remote_reference(self) -> None:
        schema = _base()
        schema["properties"]["name"] = {"$ref": "https://example.invalid/x.json"}
        with pytest.raises(ValueError, match="unsupported"):
            watch.shape(schema)


def _slots(schema: dict[str, Any]) -> list[str]:
    result: list[str] = watch.shape(schema)["container_slots"]
    return result


def _keys(schema: dict[str, Any], place: str) -> list[str]:
    result: list[str] = watch.shape(schema)["keys"][place]
    return result


class TestEveryWayToNestAContainer:
    """Each shape below was a miss in the first resolver (PR #1200 review)."""

    def test_a_container_slot_on_a_job(self) -> None:
        schema = _with(
            lambda s: s["$defs"]["job"]["properties"].update(
                sidecars={"type": "array", "items": {"$ref": "#/$defs/container_spec"}}
            )
        )
        assert "job.sidecars" in _slots(schema)

    def test_a_container_inside_an_object_property(self) -> None:
        schema = _with(
            lambda s: s["$defs"]["service"]["properties"].update(
                sandbox={
                    "type": "object",
                    "properties": {
                        "containers": {"items": {"$ref": "#/$defs/container_spec"}}
                    },
                }
            )
        )
        assert "service.sandbox" in _slots(schema)

    def test_a_map_of_containers_under_additional_properties(self) -> None:
        schema = _with(
            lambda s: s["$defs"]["service"]["properties"].update(
                helpers={"additionalProperties": {"$ref": "#/$defs/container_spec"}}
            )
        )
        assert "service.helpers" in _slots(schema)

    def test_a_container_beside_a_ref(self) -> None:
        schema = _with(
            lambda s: (
                s["$defs"].update(string_or_list={"type": ["string", "array"]})
                or s["$defs"]["service"]["properties"].update(
                    runner={
                        "$ref": "#/$defs/string_or_list",
                        "oneOf": [{"$ref": "#/$defs/container_spec"}],
                    }
                )
            )
        )
        assert "service.runner" in _slots(schema)

    def test_a_tuple_of_containers_under_prefix_items(self) -> None:
        schema = _with(
            lambda s: s["$defs"]["service"]["properties"].update(
                pair={"prefixItems": [{}, {"$ref": "#/$defs/service_hook"}]}
            )
        )
        assert "service.pair" in _slots(schema)

    def test_an_exec_hook_deep_inside_a_development_block(self) -> None:
        # The shape of develop.watch[].exec, which the first resolver missed.
        schema = _with(
            lambda s: s["$defs"]["service"]["properties"].update(
                develop={
                    "properties": {
                        "watch": {
                            "items": {
                                "properties": {"exec": {"$ref": "#/$defs/service_hook"}}
                            }
                        }
                    }
                }
            )
        )
        assert "service.develop" in _slots(schema)

    def test_a_plain_key_is_not_a_slot(self) -> None:
        assert "service.restart" not in _slots(_base())


class TestEveryWayToAddAKey:
    def test_a_key_under_any_of(self) -> None:
        schema = _with(
            lambda s: s["$defs"]["service"].update(
                anyOf=[{"properties": {"host_mounts": {}}}, {}]
            )
        )
        assert "host_mounts" in _keys(schema, "service")

    def test_a_key_under_one_of(self) -> None:
        schema = _with(
            lambda s: s["$defs"]["job"].update(oneOf=[{"properties": {"schedule": {}}}])
        )
        assert "schedule" in _keys(schema, "job")

    def test_a_key_under_if_then_else(self) -> None:
        schema = _with(
            lambda s: s["$defs"]["service"].update(
                {
                    "if": {"properties": {"a": {}}},
                    "then": {"properties": {"b": {}}},
                    "else": {"properties": {"c": {}}},
                }
            )
        )
        assert {"a", "b", "c"} <= set(_keys(schema, "service"))

    def test_a_key_under_dependent_schemas(self) -> None:
        schema = _with(
            lambda s: s["$defs"]["service"].update(
                dependentSchemas={"restart": {"properties": {"restart_delay": {}}}}
            )
        )
        assert "restart_delay" in _keys(schema, "service")

    def test_a_key_through_a_direct_ref(self) -> None:
        schema = _with(
            lambda s: (
                s["$defs"].update(extra={"properties": {"via_ref": {}}})
                or s["$defs"]["job"].update({"$ref": "#/$defs/extra"})
            )
        )
        assert "via_ref" in _keys(schema, "job")

    def test_a_grant_added_to_an_exec_hook(self) -> None:
        schema = _with(
            lambda s: s["$defs"]["service_hook"]["properties"].update(cap_add={})
        )
        assert "cap_add" in _keys(schema, "service_hook")

    def test_a_key_added_to_a_pre_start_hook(self) -> None:
        schema = _with(
            lambda s: s["$defs"]["pre_start_hook"]["properties"].update(host_pid={})
        )
        assert "host_pid" in _keys(schema, "pre_start_hook")


class TestDiff:
    def test_no_difference_reports_nothing(self) -> None:
        shape = watch.shape(_base())
        assert watch.diff(shape, copy.deepcopy(shape)) == []

    def test_added_removed_and_slot_changes_are_named(self) -> None:
        before = watch.shape(_base())
        after = watch.shape(
            _with(
                lambda s: (
                    s["$defs"]["service"]["properties"].update(
                        sidecars={"items": {"$ref": "#/$defs/container_spec"}}
                    )
                    or s["$defs"]["service"]["properties"].pop("restart")
                )
            )
        )
        lines = watch.diff(before, after)
        assert "- **added** `sidecars` (service)" in lines
        assert "- **removed** `restart` (service)" in lines
        assert any(
            line.startswith("- **new container slot** `service.sidecars`")
            for line in lines
        )

    def test_a_slot_that_disappears_is_named(self) -> None:
        before = watch.shape(_base())
        after = watch.shape(
            _with(lambda s: s["$defs"]["service"]["properties"].pop("post_start"))
        )
        assert "- **container slot gone** `service.post_start`" in watch.diff(
            before, after
        )

    def test_render_names_both_commits_and_the_next_step(self) -> None:
        text = watch.render(["- **added** `x` (service)"], "a" * 40, "b" * 40)
        assert "`aaaaaaaaaaaa`" in text and "`bbbbbbbbbbbb`" in text
        assert "--write" in text


class TestMain:
    def test_exit_0_when_upstream_matches_the_record(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: pathlib.Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        schema = _base()
        record = tmp_path / "record.json"
        record.write_text(
            json.dumps({"source": {"commit": "b" * 40}, **watch.shape(schema)}),
            encoding="utf-8",
        )
        monkeypatch.setattr(watch, "RECORD", record)
        monkeypatch.setattr(watch, "fetch", lambda: ("a" * 40, schema))
        assert watch.main([]) == 0
        assert "matches" in capsys.readouterr().out

    def test_exit_1_and_a_report_when_upstream_changed(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: pathlib.Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        record = tmp_path / "record.json"
        record.write_text(
            json.dumps({"source": {"commit": "b" * 40}, **watch.shape(_base())}),
            encoding="utf-8",
        )
        changed = _with(lambda s: s["$defs"]["job"]["properties"].update(hooks={}))
        monkeypatch.setattr(watch, "RECORD", record)
        monkeypatch.setattr(watch, "fetch", lambda: ("a" * 40, changed))
        assert watch.main([]) == 1
        assert "**added** `hooks` (job)" in capsys.readouterr().out

    def test_write_records_the_shape_and_commit(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
    ) -> None:
        record = tmp_path / "record.json"
        monkeypatch.setattr(watch, "RECORD", record)
        monkeypatch.setattr(watch, "fetch", lambda: ("c" * 40, _base()))
        assert watch.main(["--write"]) == 0
        written = json.loads(record.read_text(encoding="utf-8"))
        assert written["source"]["commit"] == "c" * 40
        assert written["container_slots"] == watch.shape(_base())["container_slots"]


class TestTheCommittedRecord:
    """``scripts/compose_spec_keys.json`` agrees with the engine."""

    def test_records_a_full_upstream_commit(self) -> None:
        assert re.fullmatch(r"[0-9a-f]{40}", RECORD["source"]["commit"])
        assert RECORD["source"]["repository"] == f"https://github.com/{watch.UPSTREAM}"

    def test_lists_every_place(self) -> None:
        assert set(RECORD["keys"]) == set(watch.PLACES)

    def test_every_recorded_slot_is_traversed_or_triaged(self) -> None:
        slots = set(RECORD["container_slots"])
        unknown = slots - TRAVERSED - set(UNTRAVERSED)
        assert not unknown, (
            f"container slots {sorted(unknown)} are in the record but the engine "
            "does not traverse them and no triage decision is recorded here. "
            "Traverse them in compose_lint._units, or add them to UNTRAVERSED "
            "with the reason."
        )

    def test_every_traversed_slot_is_still_in_the_spec(self) -> None:
        gone = TRAVERSED - set(RECORD["container_slots"])
        assert not gone, (
            f"the engine traverses {sorted(gone)}, "
            "which the recorded spec no longer has"
        )

    def test_untraversed_entries_are_still_slots(self) -> None:
        stale = set(UNTRAVERSED) - set(RECORD["container_slots"])
        assert not stale, (
            f"UNTRAVERSED lists {sorted(stale)}, which are no longer slots"
        )
