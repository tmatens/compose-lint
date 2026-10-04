"""Env files cost their size once, not once per value or service that uses them.

Two shapes multiplied a small input:

- one 130 KB `.env` value, under the per-value cap, referenced as `${X}b` from
  20,000 labels: 2.6 GB of substituted text from a 389 KB file;
- one `env_file:` named by 2,000 services: the file was scanned, parsed and
  graded once per service, over a minute for 169 KB.

Identical substituted leaves now share one result under a document-wide
budget, and services that name the same files share one parse and one grading.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint import cli
from compose_lint._limits import MAX_SUBSTITUTED_TOTAL
from compose_lint._service_env import resolve_env_files
from compose_lint.parser import _substitute_interpolation_defaults

if TYPE_CHECKING:
    from pathlib import Path

ENV_NAME = "." + "env"


def _run(
    args: list[str],
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, dict[str, Any]]:
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("NO_COLOR", "1")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    code = exc.value.code if isinstance(exc.value.code, int) else 1
    return code, json.loads(capsys.readouterr().out)


class TestSubstitutionBudget:
    def test_identical_leaves_share_one_result(self) -> None:
        big = "a" * 100_000
        data: dict[str, Any] = {"labels": {f"K{i}": "${X}b" for i in range(500)}}
        _substitute_interpolation_defaults(data, {"X": big})
        values = list(data["labels"].values())
        assert values[0] == big + "b"
        assert all(value is values[0] for value in values)

    def test_distinct_leaves_stop_at_the_budget(self) -> None:
        size = 100_000
        count = MAX_SUBSTITUTED_TOTAL // size + 10
        data: dict[str, Any] = {"labels": {f"K{i}": f"${{X}}{i}" for i in range(count)}}
        _substitute_interpolation_defaults(data, {"X": "a" * size})
        values = list(data["labels"].values())
        grown = [v for v in values if not v.startswith("${X}")]
        assert values[-1] == f"${{X}}{count - 1}"
        assert sum(len(v) for v in grown) <= MAX_SUBSTITUTED_TOTAL + count * 8

    def test_ordinary_substitution_is_unchanged(self) -> None:
        data: dict[str, Any] = {
            "image": "nginx:${TAG}",
            "privileged": "${PRIV:-false}",
            "environment": {"A": "${TAG}"},
        }
        _substitute_interpolation_defaults(data, {"TAG": "1.27"})
        assert data == {
            "image": "nginx:1.27",
            "privileged": "false",
            "environment": {"A": "${TAG}"},
        }

    def test_the_budget_ends_in_a_value_left_as_written(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        (tmp_path / ENV_NAME).write_text("X=" + "a" * 130_000 + "\n")
        labels = "".join(f"      K{i}: ${{X}}{i}\n" for i in range(200))
        (tmp_path / "compose.yml").write_text(
            f"services:\n  web:\n    image: nginx:1.27\n    labels:\n{labels}"
        )
        code, doc = _run(
            ["--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
        )
        assert [e["kind"] for e in doc["errors"]] == ["coverage_gap"]
        assert code == 2

    def test_a_value_left_as_written_is_reported(self) -> None:
        size = 100_000
        count = MAX_SUBSTITUTED_TOTAL // size + 10
        data: dict[str, Any] = {"labels": {f"K{i}": f"${{X}}{i}" for i in range(count)}}
        starved: list[str] = []
        _substitute_interpolation_defaults(data, {"X": "a" * size}, starved=starved)
        assert starved
        assert all(value.startswith("${X}") for value in starved)

    def test_ordinary_substitution_reports_nothing(self) -> None:
        data: dict[str, Any] = {"image": "nginx:${TAG}", "x": "${Y:-default}"}
        starved: list[str] = []
        _substitute_interpolation_defaults(data, {"TAG": "1.27"}, starved=starved)
        assert starved == []

    @pytest.mark.parametrize("partial", [False, True])
    def test_a_finding_past_the_budget_is_a_coverage_gap(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        partial: bool,
    ) -> None:
        """A capability supplied after the budget is spent was graded as
        written, so the CL-0024 it should raise was missing with exit 0."""
        (tmp_path / ENV_NAME).write_text("X=" + "a" * 130_000 + "\nCAP=SYS_ADMIN\n")
        pad = "".join(f"  K{i}: ${{X}}{i}\n" for i in range(70))
        (tmp_path / "compose.yml").write_text(
            f"x-pad:\n{pad}"
            "services:\n  web:\n    image: nginx:1.27\n"
            '    cap_add: ["${CAP}"]\n'
        )
        args = ["--format", "json", "compose.yml"]
        code, doc = _run(
            [*args, "--allow-partial-coverage"] if partial else args,
            tmp_path,
            monkeypatch,
            capsys,
        )
        channel = doc["warnings"] if partial else doc["errors"]
        assert [d["kind"] for d in channel] == ["coverage_gap"]
        assert "left as written" in channel[0]["message"]
        if not partial:
            assert code == 2


class TestSharedEnvFiles:
    def _project(self, tmp_path: Path) -> Path:
        (tmp_path / "app.env").write_text(
            "DB_PASSWORD=hunter2hunter2\nAPI_TOKEN=abcdefabcdef1234\nPLAIN=1\n"
        )
        (tmp_path / "other.env").write_text("API_TOKEN=${Q}\n")
        (tmp_path / "compose.yml").write_text(
            "services:\n"
            "  a:\n    image: nginx:1.27\n    env_file: app.env\n"
            "  b:\n    image: nginx:1.27\n    env_file: app.env\n"
            "    environment:\n      DB_PASSWORD: ${X}\n"
            "  c:\n    image: nginx:1.27\n    env_file: [app.env, other.env]\n"
        )
        return tmp_path

    def test_services_naming_the_same_files_share_one_key_tuple(
        self, tmp_path: Path
    ) -> None:
        project = self._project(tmp_path)
        data = {
            "services": {
                "a": {"env_file": "app.env"},
                "b": {"env_file": "app.env", "environment": {"DB_PASSWORD": "x"}},
                "c": {"env_file": ["app.env", "other.env"]},
            }
        }
        resolved = resolve_env_files(data, project)
        assert resolved["a"].available is resolved["b"].available
        assert resolved["a"].available is not resolved["c"].available
        assert {k.key for k in resolved["b"].keys} == {"API_TOKEN", "PLAIN"}
        assert resolved["a"].keys is resolved["a"].available

    def test_each_service_gets_its_own_findings(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Graded once, reported per service: a shadowed key is dropped for the
        service that shadows it, and a service naming a different file list is
        graded on its own. The same findings 0.31.0 reported."""
        _, doc = _run(
            ["--format", "json", "compose.yml"],
            self._project(tmp_path),
            monkeypatch,
            capsys,
        )
        by_service: dict[str, list[str]] = {}
        for finding in doc["findings"]:
            if (
                finding["rule_id"] == "CL-0020"
                and "with a literal value from" in (finding["message"])
            ):
                by_service.setdefault(finding["service"], []).append(
                    finding["message"].split("'")[1]
                )
        assert sorted(by_service["a"]) == ["API_TOKEN", "DB_PASSWORD"]
        assert by_service["b"] == ["API_TOKEN"]
        assert sorted(by_service["c"]) == ["API_TOKEN", "DB_PASSWORD"]
