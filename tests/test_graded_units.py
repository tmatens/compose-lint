"""Hooks and jobs are graded units (ADR-040, issue #1185).

The engine hands every container a file deploys to the rules: services,
``pre_start`` init containers, ``post_start``/``pre_stop`` exec hooks and
top-level ``jobs:``. These tests pin the unit names, what a hook inherits, the
drop rule that keeps a parent's findings off its hooks, and the surfaces that
read a finding's ``service`` field.
"""

from __future__ import annotations

import collections
import json
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import yaml

from compose_lint import cli
from compose_lint._limits import MAX_SERVICES
from compose_lint._service_env import resolve_env_files
from compose_lint._units import (
    UnitLines,
    count_units,
    unit_names,
    unit_notes,
    units,
)
from compose_lint.engine import run_rules
from compose_lint.fix import collect_edits
from compose_lint.formatters.sarif import _logical_locations, _partial_fingerprints
from compose_lint.parser import ComposeError, load_compose, load_merged, loads
from compose_lint.rules import get_registered_rules

if TYPE_CHECKING:
    from compose_lint.models import Finding

FIXTURES = Path(__file__).parent / "compose_files"
HOOKS = FIXTURES / "hooks_and_jobs.yml"

ABSENCE_RULES = {"CL-0003", "CL-0006", "CL-0007", "CL-0026"}


def _lint(text: str) -> list[Finding]:
    data, lines = loads(textwrap.dedent(text))
    return run_rules(data, lines)


def _on(findings: list[Finding], unit: str) -> set[str]:
    return {f.rule_id for f in findings if f.service == unit}


@pytest.fixture(scope="module")
def fixture_findings() -> list[Finding]:
    data, lines = load_compose(HOOKS)
    return run_rules(data, lines)


class TestUnitNames:
    def test_every_unit_carries_its_document_path(
        self, fixture_findings: list[Finding]
    ) -> None:
        assert {f.service for f in fixture_findings} == {
            "app",
            "app.pre_start[0]",
            "app.pre_start[1]",
            "app.post_start[0]",
            "bare",
            "bare.pre_start[0]",
            "jobs.migrate",
        }

    def test_unit_names_include_kind_names_of_hooks_present(self) -> None:
        data, _ = load_compose(HOOKS)
        names = unit_names(data)
        assert {"app.pre_start", "app.post_start", "bare.pre_start"} <= names
        assert "app.pre_stop" not in names
        assert "app.post_start[1]" in names

    def test_provider_services_are_not_units(self) -> None:
        data = {"services": {"p": {"provider": {"type": "x"}}, "a": {}}}
        assert [u.name for u in units(data, {})] == ["a"]


class TestPreStartHooks:
    def test_a_hook_reports_what_it_wrote(
        self, fixture_findings: list[Finding]
    ) -> None:
        assert _on(fixture_findings, "app.pre_start[0]") == {"CL-0004", "CL-0020"}
        assert _on(fixture_findings, "app.pre_start[1]") == {
            "CL-0001",
            "CL-0002",
            "CL-0018",
            "CL-0019",
        }

    def test_a_finding_on_the_hooks_first_key_keeps_its_line(self) -> None:
        # The list item and its first key share a line; comparing lines would
        # have dropped this finding as the hook's own (absence) line.
        data, lines = load_compose(HOOKS)
        found = [
            f
            for f in run_rules(data, lines)
            if f.service == "app.pre_start[0]" and f.rule_id == "CL-0004"
        ]
        assert [f.line for f in found] == [lines["services.app.pre_start[0].image"]]
        assert lines["services.app.pre_start[0]"] == found[0].line

    def test_absence_is_the_parents_finding(
        self, fixture_findings: list[Finding]
    ) -> None:
        assert _on(fixture_findings, "bare") >= ABSENCE_RULES
        assert not ABSENCE_RULES & _on(fixture_findings, "bare.pre_start[0]")

    def test_the_parents_socket_mount_is_reported_once(
        self, fixture_findings: list[Finding]
    ) -> None:
        socket = collections.Counter(
            f.service for f in fixture_findings if f.rule_id == "CL-0001"
        )
        assert socket == {"app": 1, "app.pre_start[1]": 1}

    def test_an_inherited_scalar_is_the_parents_finding(self) -> None:
        findings = _lint(
            """
            services:
              app:
                image: nginx:1.27
                privileged: true
                pre_start:
                  - image: alpine:3.20
            """
        )
        assert "CL-0002" in _on(findings, "app")
        assert "CL-0002" not in _on(findings, "app.pre_start[0]")

    def test_the_hook_sees_the_inherited_scalar(self) -> None:
        data, lines = loads(
            "services:\n  a:\n    user: root\n    pre_start:\n      - image: x\n"
        )
        hook = next(u for u in units(data, lines) if u.hook)
        assert hook.config["user"] == "root"
        assert "volumes" not in hook.config

    def test_parent_collections_are_not_inherited(self) -> None:
        data, lines = loads(
            "services:\n  a:\n    cap_add: [SYS_ADMIN]\n    pre_start:\n"
            "      - image: x\n        cap_add: [NET_ADMIN]\n"
        )
        hook = next(u for u in units(data, lines) if u.hook)
        assert hook.config["cap_add"] == ["NET_ADMIN"]

    def test_a_relative_bind_source_on_a_hook_is_resolved(self, tmp_path: Path) -> None:
        climb = "../" * (len(tmp_path.parts) + 2)
        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n"
            "  app:\n"
            "    image: nginx:1.27\n"
            "    pre_start:\n"
            "      - image: alpine:3.20\n"
            "        volumes:\n"
            f"          - {climb}var/run/docker.sock:/var/run/docker.sock\n",
            encoding="utf-8",
        )
        data, lines = load_compose(compose)
        assert "CL-0001" in _on(run_rules(data, lines), "app.pre_start[0]")

    def test_override_files_append_hooks(self, tmp_path: Path) -> None:
        base = tmp_path / "compose.yml"
        base.write_text(
            "services:\n  app:\n    image: nginx:1.27\n    pre_start:\n"
            "      - image: alpine\n",
            encoding="utf-8",
        )
        over = tmp_path / "compose.override.yml"
        over.write_text(
            "services:\n  app:\n    pre_start:\n      - image: busybox\n",
            encoding="utf-8",
        )
        merged = load_merged([base, over])
        findings = run_rules(merged.data, merged.lines)
        assert "CL-0004" in _on(findings, "app.pre_start[0]")
        assert "CL-0004" in _on(findings, "app.pre_start[1]")

    def test_a_non_mapping_hook_entry_is_not_a_unit(self) -> None:
        data = {"services": {"a": {"pre_start": ["x", {"image": "y"}]}}}
        assert [u.name for u in units(data, {})] == ["a", "a.pre_start[1]"]


class TestExecHooks:
    def test_user_root_on_an_exec_is_reported(
        self, fixture_findings: list[Finding]
    ) -> None:
        assert _on(fixture_findings, "app.post_start[0]") == {"CL-0018"}

    def test_privileged_on_an_exec_is_not_graded(
        self, fixture_findings: list[Finding]
    ) -> None:
        assert not _on(fixture_findings, "app.post_start[1]")

    def test_a_parents_privileged_is_not_reported_on_the_execs_line(self) -> None:
        findings = _lint(
            """
            services:
              app:
                image: nginx:1.27
                privileged: true
                post_start:
                  - command: ["true"]
                    privileged: false
                pre_stop:
                  - command: ["true"]
                    privileged: true
            """
        )
        assert "CL-0002" in _on(findings, "app")
        assert not _on(findings, "app.post_start[0]")
        assert not _on(findings, "app.pre_stop[0]")

    def test_a_parents_command_is_not_reported_on_the_execs_command(self) -> None:
        findings = _lint(
            """
            services:
              app:
                image: nginx:1.27
                command: "server --password=hunter2"
                post_start:
                  - command: ["true"]
            """
        )
        assert "CL-0020" in _on(findings, "app")
        assert not _on(findings, "app.post_start[0]")

    def test_an_execs_environment_is_its_own(self) -> None:
        findings = _lint(
            """
            services:
              app:
                image: nginx:1.27
                environment:
                  POSTGRES_PASSWORD: hunter2
                pre_stop:
                  - command: ["true"]
                    environment:
                      MYSQL_PASSWORD: hunter2
            """
        )
        hook = [f for f in findings if f.service == "app.pre_stop[0]"]
        assert [f.rule_id for f in hook] == ["CL-0020"]
        assert "MYSQL_PASSWORD" in hook[0].message


class TestJobs:
    def test_a_job_is_graded_as_a_service(
        self, fixture_findings: list[Finding]
    ) -> None:
        data, lines = load_compose(HOOKS)
        job = [f for f in fixture_findings if f.service == "jobs.migrate"]
        assert ABSENCE_RULES | {"CL-0002"} <= {f.rule_id for f in job}
        privileged = next(f for f in job if f.rule_id == "CL-0002")
        assert privileged.line == lines["jobs.migrate.privileged"]
        absent = next(f for f in job if f.rule_id == "CL-0006")
        assert absent.line == lines["jobs.migrate"]

    def test_a_jobs_only_file_lints(self) -> None:
        data, lines = load_compose(FIXTURES / "jobs_only.yml")
        assert "CL-0002" in _on(run_rules(data, lines), "jobs.migrate")

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            ("jobs: []\n", "'jobs' must be a mapping"),
            ("jobs:\n  m: 3\n", "job 'm' must be a mapping"),
            ("services:\n  a: {}\njobs: x\n", "'jobs' must be a mapping"),
        ],
    )
    def test_a_malformed_jobs_block_is_refused(self, text: str, message: str) -> None:
        with pytest.raises(ComposeError, match=message):
            loads(text)

    def test_a_bodiless_job_nothing_defines_is_refused(self, tmp_path: Path) -> None:
        base = tmp_path / "compose.yml"
        base.write_text("services:\n  a:\n    image: x:1\n", encoding="utf-8")
        over = tmp_path / "compose.override.yml"
        over.write_text("jobs:\n  m:\n", encoding="utf-8")
        with pytest.raises(ComposeError, match="job 'm' has no body"):
            load_merged([base, over])

    def test_a_jobs_only_overlay_merges(self, tmp_path: Path) -> None:
        base = tmp_path / "compose.yml"
        base.write_text("services:\n  a:\n    image: x:1\n", encoding="utf-8")
        over = tmp_path / "compose.override.yml"
        over.write_text(
            "jobs:\n  m:\n    image: x:1\n    privileged: true\n", encoding="utf-8"
        )
        merged = load_merged([base, over])
        assert "CL-0002" in _on(run_rules(merged.data, merged.lines), "jobs.m")

    def test_a_service_named_like_a_job_does_not_lend_it_lines(self) -> None:
        data, lines = loads(
            "services:\n"
            "  jobs.m:\n"
            "    image: x:1\n"
            "    cap_drop: [ALL]\n"
            "jobs:\n"
            "  m:\n"
            "    image: x:1\n"
            "    privileged: true\n"
        )
        findings = run_rules(data, lines)
        job_lines = {f.line for f in findings if f.service == "jobs.m"}
        assert lines["services.jobs.m.cap_drop"] not in job_lines

    def test_a_jobs_env_file_is_read(self, tmp_path: Path) -> None:
        (tmp_path / "job.env").write_text("POSTGRES_PASSWORD=hunter2\n", "utf-8")
        compose = tmp_path / "compose.yml"
        compose.write_text(
            "jobs:\n  m:\n    image: x:1\n    env_file: job.env\n", encoding="utf-8"
        )
        data, lines = load_compose(compose)
        env = resolve_env_files(data, tmp_path)
        assert set(env) == {"jobs.m"}
        findings = run_rules(data, lines, env_files=env)
        assert "CL-0020" in _on(findings, "jobs.m")

    def test_a_hooks_env_file_is_not_read(self, tmp_path: Path) -> None:
        (tmp_path / "hook.env").write_text("POSTGRES_PASSWORD=hunter2\n", "utf-8")
        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n  a:\n    image: x:1\n    pre_start:\n"
            "      - image: y:1\n        env_file: hook.env\n",
            encoding="utf-8",
        )
        data, _ = load_compose(compose)
        assert resolve_env_files(data, tmp_path) == {}


# Service bodies for the rules no `insecure_*` fixture reaches.
_EXTRA_BODIES = {
    "tmpfs_exec": {"image": "nginx:1.27", "tmpfs": ["/tmp:exec"]},
    "cap_add_ipc_lock": {"image": "nginx:1.27", "cap_add": ["IPC_LOCK"]},
    "cap_add_syslog": {"image": "nginx:1.27", "cap_add": ["SYSLOG"]},
}


def _documents(case: str, config: dict[str, Any]) -> tuple[str, str, str, str]:
    body = yaml.safe_dump(config, sort_keys=False)
    service = f"services:\n  s:\n{textwrap.indent(body, '    ')}"
    hook = "services:\n  p:\n    pre_start:\n      -\n" + textwrap.indent(
        body, "        "
    )
    job = f"jobs:\n  s:\n{textwrap.indent(body, '    ')}"
    return case, service, hook, job


def _service_and_hook_documents() -> list[tuple[str, str, str, str]]:
    """Each fixture service, as a service and as a ``pre_start`` hook and a job.

    The fixture directory holds a service per rule shape, so moving each one
    into a hook and a job and back out exercises every rule's line lookup on
    the paths those units use.
    """
    cases: list[tuple[str, str, str, str]] = []
    for path in sorted(FIXTURES.glob("insecure_*.yml")):
        try:
            data, _ = load_compose(path)
        except ComposeError:
            continue
        for name, config in data["services"].items():
            if not isinstance(config, dict) or "extends" in config:
                continue
            cases.append(_documents(f"{path.stem}:{name}", config))
    cases.extend(_documents(case, body) for case, body in _EXTRA_BODIES.items())
    return cases


_CASES = _service_and_hook_documents()


def test_the_rule_sweep_covers_every_rule() -> None:
    """Guard the guard: the sweep must reach every registered rule."""
    fired: set[str] = set()
    for _id, service, _hook, _job in _CASES:
        fired |= {f.rule_id for f in run_rules(*loads(service))}
    assert fired == {cls().metadata.id for cls in get_registered_rules()}


def _shape(findings: list[Finding], unit: str) -> collections.Counter[Any]:
    return collections.Counter(
        (f.rule_id, f.severity, f.evidence) for f in findings if f.service == unit
    )


@pytest.mark.parametrize(
    ("case", "service", "hook", "job"), _CASES, ids=[c[0] for c in _CASES]
)
def test_hooks_and_jobs_grade_what_they_wrote_like_a_service(
    case: str, service: str, hook: str, job: str
) -> None:
    """A rule that fires on a key a service writes fires on a hook writing it.

    If a rule built a line path the hook's unit name does not resolve, its
    finding would have no line and the drop rule would eat it silently.
    """
    data, lines = loads(service)
    as_service = run_rules(data, lines)
    service_line = lines["services.s"]
    written = [f for f in as_service if f.line != service_line]

    data, lines = loads(hook)
    as_hook = run_rules(data, lines)
    assert _shape(as_hook, "p.pre_start[0]") == _shape(written, "s")

    data, lines = loads(job)
    as_job = run_rules(data, lines)
    assert all(f.line is not None for f in as_job)
    assert _shape(as_job, "jobs.s") == _shape(as_service, "s")


class TestExclusions:
    def _excluded(self, names: list[str], rule: str = "CL-0004") -> dict[str, bool]:
        data, lines = load_compose(HOOKS)
        findings = run_rules(
            data, lines, excluded_services={rule: dict.fromkeys(names)}
        )
        return {f.service: f.suppressed for f in findings if f.rule_id == rule}

    def test_by_full_unit_name(self) -> None:
        assert self._excluded(["app.pre_start[0]"]) == {"app.pre_start[0]": True}

    def test_by_kind_name(self) -> None:
        result = self._excluded(["app.pre_start"])
        assert result == {"app.pre_start[0]": True}
        assert self._excluded(["app.pre_start"], "CL-0019")["app.pre_start[1]"]

    def test_a_service_exclusion_does_not_cover_its_hooks(self) -> None:
        result = self._excluded(["app"], "CL-0001")
        assert result == {"app": True, "app.pre_start[1]": False}

    def test_the_reason_names_the_exclusion_used(self) -> None:
        data, lines = load_compose(HOOKS)
        findings = run_rules(
            data,
            lines,
            excluded_services={"CL-0004": {"app.pre_start": "init image"}},
        )
        hook = next(f for f in findings if f.service == "app.pre_start[0]")
        assert hook.suppression_reason == "init image"
        assert hook.suppressed_by == (
            "excluded for service 'app.pre_start' in .compose-lint.yml"
        )


class TestIdentity:
    def test_a_hook_and_its_parent_are_distinct_alerts(self) -> None:
        findings = _lint(
            """
            services:
              app:
                image: nginx
                pre_start:
                  - image: nginx
            """
        )
        cl0004 = [f for f in findings if f.rule_id == "CL-0004"]
        assert {f.service for f in cl0004} == {"app", "app.pre_start[0]"}
        assert cl0004[0].evidence == cl0004[1].evidence
        prints = {json.dumps(_partial_fingerprints("compose.yml", f)) for f in cl0004}
        assert len(prints) == 2

    def test_sarif_names_the_unit(self, fixture_findings: list[Finding]) -> None:
        names = {
            location["name"]
            for finding in fixture_findings
            for location in _logical_locations(finding)
        }
        assert {"app.pre_start[0]", "jobs.migrate"} <= names


class TestQuoting:
    def test_a_env_value_in_a_hook_is_quoted(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("TAG=s3cr3t-registry-token\n", "utf-8")
        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n  a:\n    image: x:1\n    pre_start:\n"
            "      - image: registry.example/app:${TAG}\n",
            encoding="utf-8",
        )
        from compose_lint.parser import load_compose_full

        loaded = load_compose_full(compose)
        findings = run_rules(loaded.data, loaded.lines, env_values=loaded.env_values)
        hook = [f for f in findings if f.service == "a.pre_start[0]"]
        assert hook
        for finding in hook:
            assert "s3cr3t-registry-token" not in finding.message
            assert "s3cr3t-registry-token" not in (finding.fix or "")


class TestFix:
    def test_hook_and_job_findings_are_reported_not_edited(self) -> None:
        text = HOOKS.read_text(encoding="utf-8")
        data, lines = loads(text)
        findings = run_rules(data, lines)
        result = collect_edits(findings, data, lines, text)
        units_left = {
            f.service for f in result.manual if f.service not in {"app", "bare"}
        }
        assert {"app.pre_start[0]", "jobs.migrate"} <= units_left
        assert not any(f.service not in {"app", "bare"} for f in result.fixed)
        assert any("hook and job units are reported" in n for n in result.notes)

    def test_a_service_sharing_a_jobs_name_is_not_edited(self) -> None:
        text = "services:\n  jobs.m:\n    image: x:1\njobs:\n  m:\n    image: x:1\n"
        data, lines = loads(text)
        result = collect_edits(run_rules(data, lines), data, lines, text)
        assert not result.fixed
        assert not result.edits


class TestUnitLines:
    def test_mapping_protocol_agrees_with_get(self) -> None:
        view = UnitLines(
            {"a": 1, "a.b": 2, "c": 3, "jobs.x": 9},
            hidden=frozenset({"a"}),
            hidden_trees=("c",),
            alias={"services.jobs.x": 9},
            alias_prefix="services.jobs.x",
        )
        assert view.get("a") is None
        assert view.get("a.b") == 2
        assert view.get("c") is None
        assert view.get("services.jobs.x") == 9
        assert view.get("services.jobs.x.y") is None
        assert not view.__contains__(1)  # a non-string key is never a path
        assert sorted(view) == ["a.b", "jobs.x", "services.jobs.x"]
        assert len(view) == 3


class TestCli:
    def _main(
        self,
        args: list[str],
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> tuple[int, str, str]:
        monkeypatch.setenv("NO_COLOR", "1")
        capsys.readouterr()
        with pytest.raises(SystemExit) as exc:
            cli.main(args)
        out = capsys.readouterr()
        code = exc.value.code if isinstance(exc.value.code, int) else 1
        return code, out.out, out.err

    def test_json_reports_unit_names(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, out, _ = self._main(["--format", "json", str(HOOKS)], capsys, monkeypatch)
        services = {f["service"] for f in json.loads(out)["findings"]}
        assert {"app.pre_start[0]", "app.post_start[0]", "jobs.migrate"} <= services

    def test_text_groups_under_unit_names(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, out, _ = self._main([str(HOOKS)], capsys, monkeypatch)
        assert "service: app.pre_start[0]" in out
        assert "service: jobs.migrate" in out

    def test_a_jobs_only_file_is_not_refused(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        code, out, err = self._main(
            ["--format", "json", str(FIXTURES / "jobs_only.yml")], capsys, monkeypatch
        )
        assert code == 1
        assert "missing 'services' key" not in err
        assert any(f["rule_id"] == "CL-0002" for f in json.loads(out)["findings"])

    def test_kind_names_are_known_to_the_unknown_name_warning(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        config = tmp_path / "cfg.yml"
        config.write_text(
            "rules:\n  CL-0004:\n    exclude_services:\n"
            "      - app.pre_start\n      - app.pre_start[0]\n"
            "      - jobs.migrate\n      - app.pre_stop\n",
            encoding="utf-8",
        )
        _, _, err = self._main(
            ["--config", str(config), str(HOOKS)], capsys, monkeypatch
        )
        unknown = [line for line in err.splitlines() if "unknown service" in line]
        assert len(unknown) == 1
        assert "'app.pre_stop'" in unknown[0]

    def test_fix_reports_hook_findings_by_hand(
        self, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, _, err = self._main(["fix", str(HOOKS)], capsys, monkeypatch)
        assert "hook and job units are reported, not edited" in err


class TestBounds:
    def _over(self) -> str:
        hooks = "".join("      - {}\n" for _ in range(MAX_SERVICES))
        return f"services:\n  a:\n    image: x:1\n    pre_start:\n{hooks}"

    def test_past_the_bound_only_services_are_graded(self) -> None:
        data, lines = loads(self._over())
        assert [u.name for u in units(data, lines)] == ["a"]
        notes = unit_notes(data)
        assert len(notes) == 1
        assert "only its services were graded" in notes[0]
        assert "next minor release" in notes[0]

    def test_an_aliased_hook_list_counts_per_service(self) -> None:
        per = 64
        services = MAX_SERVICES // per + 1
        text = (
            "x-hooks: &hooks\n"
            + "".join("  - {image: 'x:1'}\n" for _ in range(per))
            + "services:\n"
            + "".join(f"  s{i}:\n    pre_start: *hooks\n" for i in range(services))
        )
        data, lines = loads(text)
        assert count_units(data) > MAX_SERVICES
        assert all(not u.hook for u in units(data, lines))

    def test_units_count_services_hooks_and_jobs(self) -> None:
        doc = {
            "services": {"a": {"post_start": [{}, {}], "pre_stop": [{}]}, 1: {}},
            "jobs": {"m": {}, "n": {}},
        }
        assert count_units(doc) == 6

    def test_the_cli_warns_and_keeps_the_exit_code(
        self,
        tmp_path: Path,
    ) -> None:
        compose = tmp_path / "compose.yml"
        compose.write_text(self._over(), encoding="utf-8")
        proc = _cli(["--format", "json", "--fail-on", "critical", str(compose)])
        assert proc.returncode == 0
        warnings = json.loads(proc.stdout)["warnings"]
        assert [w["kind"] for w in warnings] == ["unread_input"]


class TestExtendedJobs:
    def _write(self, tmp_path: Path) -> Path:
        compose = tmp_path / "compose.yml"
        compose.write_text(
            "services:\n  a:\n    image: x:1@sha256:"
            + "0" * 64
            + "\n    read_only: true\n    cap_drop: [ALL]\n"
            "    security_opt: [no-new-privileges:true]\n"
            "jobs:\n"
            "  base:\n    image: x:1\n    cap_drop: [ALL]\n"
            "  child:\n    extends: base\n    command: ['true']\n",
            encoding="utf-8",
        )
        return compose

    def test_an_extended_job_is_not_graded(self, tmp_path: Path) -> None:
        data, lines = load_compose(self._write(tmp_path))
        services = {f.service for f in run_rules(data, lines)}
        assert "jobs.base" in services
        assert "jobs.child" not in services
        assert unit_notes(data) == [
            "job 'child' uses 'extends:', which compose-lint does not resolve "
            "for jobs yet, so the job was not graded; from the next minor "
            "release this is a coverage gap (exit 2)"
        ]

    def test_the_cli_warns_without_exiting_2(self, tmp_path: Path) -> None:
        proc = _cli(
            ["--format", "json", "--fail-on", "critical", str(self._write(tmp_path))]
        )
        assert proc.returncode == 0
        warnings = json.loads(proc.stdout)["warnings"]
        assert any("job 'child'" in w["message"] for w in warnings)
        assert "note:" in proc.stderr

    def test_fix_and_init_say_it_too(self, tmp_path: Path) -> None:
        compose = self._write(tmp_path)
        assert "job 'child'" in _cli(["fix", str(compose)]).stderr
        out = tmp_path / "baseline.yml"
        init = _cli(["init", str(compose), "--output", str(out)])
        assert "job 'child'" in init.stderr


def _cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "compose_lint", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
