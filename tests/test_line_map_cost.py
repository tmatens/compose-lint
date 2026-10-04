"""The line map grows with the file, not with the paths that reach a node.

A line or tag record was written once per path to a node, and once more per
``extends:`` child for every line it inherits. Four inputs multiplied that into
tens of millions of entries from a few hundred kilobytes:

- one ``labels:`` anchor aliased into 4,000 services (``_collect_lines``);
- the same through a merge key (``<<: *m``), which copies the reference;
- a mapping of ``!reset`` keys aliased the same way (``_collect_tagged``);
- 2,000 in-file ``extends:`` children of one 4,000-label base.

Repeats now spend one budget per load. A fifth cost, grouping the line map by
service, cut every path at every dot of a service name; it is now one check per
related name.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from compose_lint import cli
from compose_lint.parser import (
    _collect_lines,
    _collect_tagged,
    _lines_by_service,
    _loads_full,
    _RepeatBudget,
    loads,
)

if TYPE_CHECKING:
    from pathlib import Path


def _shared_labels(services: int, keys: int) -> str:
    out = ["x-l: &lab"] + [f"  K{i}: v" for i in range(keys)] + ["services:"]
    for j in range(services):
        out += [f"  s{j}:", "    image: nginx:1.27", "    labels: *lab"]
    return "\n".join(out) + "\n"


def _extends_children(keys: int, children: int) -> str:
    out = ["services:", "  base:", "    image: nginx:1.27", "    labels:"]
    out += [f"      K{i}: v" for i in range(keys)]
    for j in range(children):
        out += [f"  c{j}:", "    extends: base"]
    return "\n".join(out) + "\n"


class TestBudget:
    def test_take_spends_only_what_is_left(self) -> None:
        budget = _RepeatBudget(10)
        assert budget.take(4)
        assert budget.take(6)
        assert not budget.take(1)
        assert budget.remaining == 0

    def test_a_refused_take_spends_the_rest(self) -> None:
        """Once one repeat is refused, none after it fits either."""
        budget = _RepeatBudget(10)
        assert not budget.take(11)
        assert not budget.take(1)


class TestAliasedMapping:
    def test_realistic_sharing_is_recorded_under_every_service(self) -> None:
        """#279 E3: each service that aliases the anchor gets its own lines."""
        data, lines = loads(_shared_labels(5, 3))
        assert data["services"]["s4"]["labels"]["K2"] == "v"
        for j in range(5):
            assert f"services.s{j}.labels.K2" in lines

    def test_repeats_stop_at_the_budget(self) -> None:
        text = _shared_labels(50, 100)
        data, lines, *_ = _loads_full(text, repeats=_RepeatBudget(1000))
        labelled = [j for j in range(50) if f"services.s{j}.labels.K99" in lines]
        # One path is free and the rest spend 1,000: about ten services' worth.
        assert 5 <= len(labelled) <= 12
        assert len(lines) < 50 * 100
        # Every service still parses and is graded with its full labels.
        assert all(len(data["services"][f"s{j}"]["labels"]) == 100 for j in range(50))
        # A service's own keys keep their lines whatever the budget.
        assert all(f"services.s{j}.image" in lines for j in range(50))

    def test_a_merge_key_is_bounded_the_same_way(self) -> None:
        out = ["x-m: &m", "  labels:"] + [f"    K{i}: v" for i in range(100)]
        out += ["services:"]
        for j in range(50):
            out += [f"  s{j}:", "    <<: *m", "    image: nginx:1.27"]
        _, lines, *_ = _loads_full("\n".join(out) + "\n", repeats=_RepeatBudget(500))
        assert len(lines) < 50 * 100


class TestTaggedKeys:
    def test_a_shared_reset_mapping_is_bounded(self) -> None:
        out = ["x-r: &r"] + [f"  K{i}: !reset v" for i in range(100)]
        out += ["services:"]
        for j in range(50):
            out += [f"  s{j}:", "    image: nginx:1.27", "    labels: *r"]
        _, _, resets, _, _ = _loads_full(
            "\n".join(out) + "\n", repeats=_RepeatBudget(1000)
        )
        tagged = {path.split(".")[1] for path in resets if path.startswith("services.")}
        assert 5 <= len(tagged) <= 12
        assert len(resets) <= 100 + 1000 + 100

    def test_collect_tagged_records_the_first_path_for_free(self) -> None:
        shared: dict[str, str] = {"a": "x"}
        data = {"one": shared, "two": shared}
        found = _collect_tagged(data, {id(shared): {"a"}}, repeats=_RepeatBudget(0))
        assert len(found) == 1

    def test_a_refused_repeat_is_reported(self) -> None:
        shared: dict[str, str] = {"a": "x"}
        data = {"one": shared, "two": shared}
        dropped: list[str] = []
        _collect_tagged(
            data, {id(shared): {"a"}}, repeats=_RepeatBudget(0), dropped=dropped
        )
        assert len(dropped) == 1
        assert dropped[0] in ("one", "two")

    def test_a_repeat_within_the_budget_is_not_reported(self) -> None:
        shared: dict[str, str] = {"a": "x"}
        data = {"one": shared, "two": shared}
        dropped: list[str] = []
        found = _collect_tagged(
            data, {id(shared): {"a"}}, repeats=_RepeatBudget(10), dropped=dropped
        )
        assert len(found) == 2
        assert dropped == []


def _dropped_reset(keys: int, aliases: int) -> str:
    """A ``!reset`` service reached by a second path after aliases spent the budget.

    Compose deletes the base's hardening in ``app``; with the reset dropped
    the merge kept it, and CL-0003/CL-0006 were missing with exit 0.
    """
    out = ["x-big: &big"] + [f"  k{i}: v" for i in range(keys)]
    out.append("x-rep: [" + ", ".join(["*big"] * aliases) + "]")
    out += [
        "x-child: &child",
        "  image: alpine:3.20",
        "  extends: base",
        "  cap_drop: !reset []",
        "  security_opt: !reset []",
        "services:",
        "  base:",
        "    image: alpine:3.20",
        "    cap_drop: [ALL]",
        '    security_opt: ["no-new-privileges:true"]',
        "  app: *child",
        "x-zzz: [*child]",
    ]
    return "\n".join(out) + "\n"


@pytest.mark.parametrize("partial", [False, True])
def test_a_dropped_reset_is_a_coverage_gap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    partial: bool,
) -> None:
    (tmp_path / "compose.yml").write_text(_dropped_reset(1000, 300))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NO_COLOR", "1")
    args = ["--format", "json", "compose.yml"]
    with pytest.raises(SystemExit) as exc:
        cli.main([*args, "--allow-partial-coverage"] if partial else args)
    doc = json.loads(capsys.readouterr().out)
    channel = doc["warnings"] if partial else doc["errors"]
    assert [d["kind"] for d in channel] == ["coverage_gap"]
    assert "!reset/!override" in channel[0]["message"]
    if not partial:
        assert exc.value.code == 2


def test_a_reset_reached_twice_within_the_budget_is_applied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "compose.yml").write_text(_dropped_reset(10, 3))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NO_COLOR", "1")
    with pytest.raises(SystemExit):
        cli.main(["--format", "json", "compose.yml"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["errors"] == []
    rules = {f["rule_id"] for f in doc["findings"] if f["service"] == "app"}
    assert {"CL-0003", "CL-0006"} <= rules


class TestExtendsChildren:
    def test_children_inherit_lines_within_the_budget(self) -> None:
        _, lines = loads(_extends_children(10, 3))
        for j in range(3):
            assert f"services.c{j}.labels.K9" in lines

    def test_children_past_the_budget_keep_their_own_lines(self) -> None:
        data, lines, *_ = _loads_full(
            _extends_children(100, 50), repeats=_RepeatBudget(1000)
        )
        inherited = [j for j in range(50) if f"services.c{j}.labels.K99" in lines]
        assert 0 < len(inherited) < 50
        assert all(f"services.c{j}.extends" in lines for j in range(50))
        assert all(len(data["services"][f"c{j}"]["labels"]) == 100 for j in range(50))


class TestLinesByService:
    LINES = {
        "services.web": 1,
        "services.web.image": 2,
        "services.web.ports[0]": 3,
        "services.webx": 4,
        "services.webx.image": 5,
        "services.a.b": 6,
        "services.a.b.image": 7,
        "services.c.d": 8,
        "services.c.d.image": 9,
        "networks.web.driver": 10,
    }
    SERVICES: dict[str, dict[str, str]] = {
        "web": {},
        "webx": {},
        "a": {},
        "a.b": {},
        "c.d": {},
    }

    def test_a_name_that_extends_another_is_not_its_prefix(self) -> None:
        grouped = _lines_by_service(self.LINES, self.SERVICES, ["web", "webx"])
        assert grouped["web"] == {
            "services.web": 1,
            "services.web.image": 2,
            "services.web.ports[0]": 3,
        }
        assert grouped["webx"] == {"services.webx": 4, "services.webx.image": 5}

    def test_the_shortest_declared_name_owns_a_path(self) -> None:
        """`services.a.b.image` is service `a`'s whenever `a` is declared."""
        grouped = _lines_by_service(self.LINES, self.SERVICES, ["a", "a.b", "c.d"])
        assert "a.b" not in grouped
        assert grouped["a"]["services.a.b.image"] == 7
        assert grouped["c.d"] == {"services.c.d": 8, "services.c.d.image": 9}

    def test_only_wanted_services_are_grouped(self) -> None:
        assert list(_lines_by_service(self.LINES, self.SERVICES, ["webx"])) == ["webx"]

    def test_a_many_dotted_name_is_one_pass(self) -> None:
        """Every path under a 4,000-dot name was cut at every dot."""
        name = ".".join(["a"] * 4000)
        lines = {f"services.{name}.labels.K{i}": i for i in range(1000)}
        grouped = _lines_by_service(lines, {name: {}}, [name])
        assert len(grouped[name]) == 1000


def test_collect_lines_defaults_to_a_fresh_budget() -> None:
    shared: dict[str, str] = {"a": "x"}
    assert _collect_lines({"one": shared, "two": shared}) == {}
