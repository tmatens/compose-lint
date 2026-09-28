"""A document that multiplies its findings stops being graded, and says so.

A rule reports one finding per item it grades, and an aliased list is one set
of items shared by every service: a 1,000-entry `ports:` anchor in 2,000
services was two million findings, built and graded before anything was
printed, and ran out of memory. Past MAX_FINDINGS the engine stops, and what it
did not grade is a coverage gap.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint import cli, engine
from compose_lint.engine import FindingLimitError, run_rules
from compose_lint.parser import loads

if TYPE_CHECKING:
    from pathlib import Path

LIMIT = 50


def _shared_ports(items: int, services: int) -> str:
    out = ["x-p: &p"] + [f"  - '{8000 + i}:80'" for i in range(items)]
    out.append("services:")
    for j in range(services):
        out += [f"  s{j}:", "    image: nginx:1.27", "    ports: *p"]
    return "\n".join(out) + "\n"


@pytest.fixture(autouse=True)
def _small_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(engine, "MAX_FINDINGS", LIMIT)


def _run(
    args: list[str],
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, str, str]:
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("NO_COLOR", "1")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    captured = capsys.readouterr()
    code = exc.value.code if isinstance(exc.value.code, int) else 1
    return code, captured.out, captured.err


def test_the_engine_stops_past_the_limit() -> None:
    data, lines = loads(_shared_ports(20, 20))
    with pytest.raises(FindingLimitError) as caught:
        run_rules(data, lines)
    graded = caught.value.findings
    assert LIMIT < len(graded) <= LIMIT + 20 * 20
    assert graded == sorted(graded, key=lambda f: (f.line is None, f.line or 0))


def test_a_document_under_the_limit_is_unaffected() -> None:
    data, lines = loads(_shared_ports(2, 2))
    assert len(run_rules(data, lines)) < LIMIT


@pytest.mark.parametrize("fmt", ["json", "sarif", "text"])
def test_check_reports_a_coverage_gap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    fmt: str,
) -> None:
    (tmp_path / "compose.yml").write_text(_shared_ports(20, 20))
    code, out, err = _run(
        ["--format", fmt, "compose.yml"], tmp_path, monkeypatch, capsys
    )
    assert code == 2
    assert f"grading stopped at {LIMIT} findings" in err
    if fmt == "json":
        doc: dict[str, Any] = json.loads(out)
        assert [e["kind"] for e in doc["errors"]] == ["coverage_gap"]
        assert len(doc["findings"]) > LIMIT
    elif fmt == "sarif":
        invocation = json.loads(out)["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False


def test_allow_partial_coverage_grades_what_was_seen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "compose.yml").write_text(_shared_ports(20, 20))
    code, out, _ = _run(
        ["--format", "json", "--allow-partial-coverage", "compose.yml"],
        tmp_path,
        monkeypatch,
        capsys,
    )
    doc = json.loads(out)
    assert doc["errors"] == []
    assert [w["kind"] for w in doc["warnings"]] == ["coverage_gap"]
    assert code in (0, 1)


@pytest.mark.parametrize(
    ("command", "outcome"),
    [("fix", "No fixes computed or written."), ("init", "No baseline written.")],
)
def test_fix_and_init_refuse_a_partial_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    outcome: str,
) -> None:
    compose = tmp_path / "compose.yml"
    compose.write_text(_shared_ports(20, 20))
    before = compose.read_text()
    args = (
        [command, "--apply", "compose.yml"]
        if command == "fix"
        else [command, "compose.yml"]
    )
    code, _, err = _run(args, tmp_path, monkeypatch, capsys)
    assert code == 2
    assert outcome in err
    assert compose.read_text() == before
    assert not (tmp_path / ".compose-lint.yml").exists()
