"""`-f a.yaml -f b.yaml`: several files named as one project (ADR-044).

Compose picks its documents three ways, and an explicit `-f` is the first of
them. These tests pin that compose-lint plans a `-f` list the way Compose loads
it: in the order given, with nothing added and nothing dropped, against the
first file's directory. The Compose behaviour each one mirrors was measured on
Compose 5.5.0 and 5.8.0; the tests marked `requires_docker` re-measure it
against whichever Compose is installed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

from compose_lint import cli
from compose_lint._selection import MergeReason, plan_documents
from compose_lint.parser import load_merged, merge_patched
from tests.oracle_harness import compose_argv

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

requires_docker = pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="needs the docker compose CLI",
)

# The layout from the request: a shared service declared in the base, and each
# overlay attaching it to that overlay's network.
BASE = """\
services:
  reverse-proxy:
    image: traefik:v3
    networks:
      - traefik
networks:
  traefik: {}
"""
OVERLAY_A = """\
networks:
  service-a: {}
services:
  reverse-proxy:
    networks:
      - service-a
  service-a:
    image: example/service-a:1
    networks:
      - service-a
"""
PRIVILEGED = "services:\n  reverse-proxy:\n    privileged: true\n"
UNPRIVILEGED = "services:\n  reverse-proxy:\n    privileged: false\n"
# Each publishes a port on every interface, which `fix` rewrites.
FIXABLE_BASE = """\
services:
  reverse-proxy:
    image: traefik:v3
    ports:
      - "80:80"
"""
FIXABLE_OVERLAY = """\
services:
  service-a:
    image: example/a:1
    ports:
      - "81:81"
"""


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="")
    return path


@pytest.fixture
def project(tmp_path: Path) -> Iterator[Path]:
    """A base and one overlay in a subdirectory, with the run started beside it."""
    write(tmp_path / "compose.yaml", BASE)
    write(tmp_path / "svc" / "a.yaml", OVERLAY_A)
    previous = os.getcwd()
    os.chdir(tmp_path)
    try:
        yield tmp_path
    finally:
        os.chdir(previous)


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "compose_lint", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=cwd,
    )


def compose_services(*files: str, cwd: Path) -> dict[str, dict]:
    """The services `docker compose -f ... config` renders for ``files``."""
    argv = [*compose_argv()]
    for name in files:
        argv += ["-f", name]
    result = subprocess.run(
        [*argv, "config", "--format", "json"],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    services: dict[str, dict] = json.loads(result.stdout)["services"]
    return services


class TestSelection:
    """What `plan_documents` returns for a `-f` list."""

    def test_the_list_is_one_group_in_the_order_given(self, project: Path) -> None:
        selection = plan_documents([], project_files=["compose.yaml", "svc/a.yaml"])
        (group,) = selection.groups
        assert group.paths == ["compose.yaml", "svc/a.yaml"]
        assert group.reason is MergeReason.FLAG
        assert not selection.gaps

    def test_a_single_file_is_a_group_with_nothing_merged(self, project: Path) -> None:
        (group,) = plan_documents([], project_files=["compose.yaml"]).groups
        assert group.paths == ["compose.yaml"]

    def test_a_repeated_file_is_kept(self, project: Path) -> None:
        """Compose merges it again, so dropping it grades a different project."""
        names = ["compose.yaml", "svc/a.yaml", "compose.yaml"]
        (group,) = plan_documents([], project_files=names).groups
        assert group.paths == names

    def test_compose_file_in_the_env_file_is_not_used(self, project: Path) -> None:
        write(project / "other.yaml", PRIVILEGED)
        write(project / ".env", "COMPOSE_FILE=compose.yaml:other.yaml\n")
        selection = plan_documents([], project_files=["compose.yaml", "svc/a.yaml"])
        assert selection.groups[0].paths == ["compose.yaml", "svc/a.yaml"]
        (note,) = selection.notes
        assert "COMPOSE_FILE was not used" in note
        assert selection.env_files == (".env",)

    def test_a_list_that_would_be_refused_is_not_a_gap(self, project: Path) -> None:
        """`-f` never uses the list, so a bad entry in it cannot fail the run."""
        write(project / ".env", "COMPOSE_FILE=compose.yaml:missing.yaml\n")
        selection = plan_documents([], project_files=["compose.yaml"])
        assert not selection.gaps
        assert len(selection.groups) == 1

    def test_no_env_reads_nothing_and_says_nothing(self, project: Path) -> None:
        write(project / ".env", "COMPOSE_FILE=compose.yaml\n")
        selection = plan_documents(
            [], project_files=["compose.yaml"], read_env_files=False
        )
        assert not selection.notes
        assert not selection.env_files

    def test_an_unreadable_env_file_is_still_a_gap(self, project: Path) -> None:
        """Its values are read for `-f` too, so not reading it is a gap."""
        (project / ".env").write_bytes(b"P=\xff\n")
        selection = plan_documents([], project_files=["compose.yaml"])
        ((path, message),) = selection.gaps
        assert path == ".env"
        assert "not read because" in message
        assert len(selection.groups) == 1

    def test_the_override_beside_the_base_is_not_merged(self, project: Path) -> None:
        write(project / "compose.override.yml", PRIVILEGED)
        selection = plan_documents([], project_files=["compose.yaml"])
        assert selection.groups[0].paths == ["compose.yaml"]
        (note,) = selection.notes
        assert note.startswith("compose.override.yml: not merged")

    @pytest.mark.parametrize("position", [0, 1])
    def test_a_link_out_of_the_repository_stops_the_project(
        self, project: Path, tmp_path_factory: pytest.TempPathFactory, position: int
    ) -> None:
        """No partial merge and no promoted base: either is a project Compose
        never loads."""
        outside = write(tmp_path_factory.mktemp("outside") / "x.yaml", PRIVILEGED)
        (project / "linked.yaml").symlink_to(outside)
        names = ["compose.yaml", "svc/a.yaml"]
        names.insert(position, "linked.yaml")
        selection = plan_documents([], project_files=names)
        assert not selection.groups
        ((path, message),) = selection.gaps
        assert path == "linked.yaml"
        assert "the project was not linted" in message


class TestMergeMatchesCompose:
    """The merged project, against Compose where it is installed."""

    def test_a_repeated_file_is_applied_again(self, project: Path) -> None:
        write(project / "a.yaml", PRIVILEGED.replace("privileged: true", "image: one"))
        write(project / "b.yaml", PRIVILEGED.replace("privileged: true", "image: two"))
        once = load_merged(["a.yaml", "b.yaml"])
        again = load_merged(["a.yaml", "b.yaml", "a.yaml"])
        assert once.data["services"]["reverse-proxy"]["image"] == "two"
        assert again.data["services"]["reverse-proxy"]["image"] == "one"

    @requires_docker
    def test_compose_applies_a_repeated_file_again(self, project: Path) -> None:
        write(project / "a.yaml", PRIVILEGED.replace("privileged: true", "image: one"))
        write(project / "b.yaml", PRIVILEGED.replace("privileged: true", "image: two"))
        once = compose_services("a.yaml", "b.yaml", cwd=project)
        again = compose_services("a.yaml", "b.yaml", "a.yaml", cwd=project)
        assert once["reverse-proxy"]["image"] == "two"
        assert again["reverse-proxy"]["image"] == "one"

    def _outside_project(self, root: Path) -> None:
        """A base in `proj/` and an overlay in `other/`, each with its own
        `ext.yaml` and `inc.yaml`, so where a reference resolved is visible."""
        write(root / "proj" / "a.yaml", "services:\n  web:\n    image: nginx:1\n")
        write(
            root / "other" / "c.yaml",
            "include:\n  - ./inc.yaml\n"
            "services:\n  web:\n    volumes:\n      - ./data:/data\n"
            "  fromc:\n    extends:\n      file: ./ext.yaml\n      service: base\n",
        )
        for directory in ("proj", "other"):
            write(
                root / directory / "ext.yaml",
                f"services:\n  base:\n    image: ext-in-{directory}\n",
            )
            write(
                root / directory / "inc.yaml",
                f"services:\n  inc_{directory}:\n    image: inc-in-{directory}\n",
            )

    def test_an_overlay_elsewhere_resolves_against_the_first_file(
        self, project: Path
    ) -> None:
        """`extends: file:`, `include:` and a relative mount written in an
        overlay all resolve against the first file's directory."""
        self._outside_project(project)
        merged = load_merged(["proj/a.yaml", "other/c.yaml"])
        services = merged.data["services"]
        assert services["fromc"]["image"] == "ext-in-proj"
        assert "inc_proj" in services
        assert "inc_other" not in services
        (volume,) = services["web"]["volumes"]
        # The engine spells a resolved source in POSIX notation on every
        # platform, so compare the tail rather than this host's own spelling.
        source = volume.removesuffix(":/data")
        assert source.endswith("/proj/data")
        assert "/other/" not in source
        assert not merged.gaps

    @requires_docker
    def test_compose_resolves_an_overlay_elsewhere_the_same_way(
        self, project: Path
    ) -> None:
        self._outside_project(project)
        services = compose_services("proj/a.yaml", "other/c.yaml", cwd=project)
        assert services["fromc"]["image"] == "ext-in-proj"
        assert "inc_proj" in services
        assert "inc_other" not in services
        (volume,) = services["web"]["volumes"]
        assert volume["source"] == str(project / "proj" / "data")

    @requires_docker
    def test_compose_gives_f_precedence_over_the_other_two_paths(
        self, project: Path
    ) -> None:
        """`-f` skips the override and a `COMPOSE_FILE` in `.env`."""
        write(project / "compose.override.yml", PRIVILEGED)
        write(project / "extra.yaml", PRIVILEGED)
        write(project / ".env", "COMPOSE_FILE=compose.yaml:extra.yaml\n")
        services = compose_services("compose.yaml", "svc/a.yaml", cwd=project)
        assert "privileged" not in services["reverse-proxy"]
        assert sorted(services["reverse-proxy"]["networks"]) == ["service-a", "traefik"]

    def test_a_fix_to_a_repeated_base_is_verified_against_itself(
        self, project: Path
    ) -> None:
        """The later copy of the base is the file the patch rewrites, so it is
        the patched text too, not the text on disk."""
        write(project / "a.yaml", PRIVILEGED)
        write(project / "b.yaml", "services:\n  reverse-proxy:\n    image: i\n")
        data, _ = merge_patched(UNPRIVILEGED, "a.yaml", ["b.yaml", "a.yaml"])
        assert data["services"]["reverse-proxy"]["privileged"] is False


class TestCheck:
    """`check -f`, end to end."""

    def test_the_shared_service_is_graded_once(self, project: Path) -> None:
        separate = run_cli(
            "--format", "json", "compose.yaml", "svc/a.yaml", cwd=project
        )
        merged = run_cli(
            "--format", "json", "-f", "compose.yaml", "-f", "svc/a.yaml", cwd=project
        )

        def per_rule(result: subprocess.CompletedProcess[str]) -> list[str]:
            return sorted(
                finding["rule_id"]
                for finding in json.loads(result.stdout)["findings"]
                if finding["service"] == "reverse-proxy"
            )

        assert len(per_rule(merged)) == len(set(per_rule(merged)))
        assert len(per_rule(separate)) > len(per_rule(merged))
        assert "because -f names them as one project" in merged.stderr

    def test_a_finding_names_the_file_it_was_written_in(self, project: Path) -> None:
        write(project / "svc" / "a.yaml", OVERLAY_A + "    privileged: true\n")
        result = run_cli(
            "--format", "json", "-f", "compose.yaml", "-f", "svc/a.yaml", cwd=project
        )
        assert result.returncode == 1
        (finding,) = (
            f
            for f in json.loads(result.stdout)["findings"]
            if f["rule_id"] == "CL-0002"
        )
        assert finding["file"] == "svc/a.yaml"
        assert finding["service"] == "service-a"

    def test_sarif_locates_the_finding_in_the_overlay(self, project: Path) -> None:
        write(project / "svc" / "a.yaml", OVERLAY_A + "    privileged: true\n")
        result = run_cli(
            "--format", "sarif", "-f", "compose.yaml", "-f", "svc/a.yaml", cwd=project
        )
        (hit,) = (
            r
            for r in json.loads(result.stdout)["runs"][0]["results"]
            if r["ruleId"] == "CL-0002"
        )
        location = hit["locations"][0]["physicalLocation"]["artifactLocation"]
        assert location["uri"] == "svc/a.yaml"

    def test_a_service_header_gives_a_line_only_for_the_first_file(
        self, project: Path
    ) -> None:
        """The header's line belongs to the file the report is headed by. A
        service with a finding written elsewhere gets no line there, because
        the first line in its group can be another file's."""
        write(
            project / "compose.yaml",
            "services:\n  reverse-proxy:\n    image: traefik:v3\n"
            "  base-only:\n    image: example/base:1\n",
        )
        # The overlay gives reverse-proxy a finding of its own (the port) and
        # declares service-a, which the base never mentions.
        write(
            project / "svc" / "a.yaml",
            'services:\n  reverse-proxy:\n    ports:\n      - "81:81"\n'
            "  service-a:\n    image: example/a:1\n",
        )
        argv = ["-f", "compose.yaml", "-f", "svc/a.yaml"]
        text = run_cli(*argv, cwd=project).stdout
        headers = {
            line.strip().split("  ")[0]: line.strip()
            for line in text.splitlines()
            if line.strip().startswith("service:")
        }
        assert headers["service: reverse-proxy"] == "service: reverse-proxy"
        assert headers["service: service-a"] == "service: service-a"

        # base-only has every finding in the first file, so its header keeps a
        # line, and it is one of that service's own lines in that file.
        findings = json.loads(run_cli("--format", "json", *argv, cwd=project).stdout)[
            "findings"
        ]
        base_only = [f for f in findings if f["service"] == "base-only"]
        assert base_only
        assert {f["file"] for f in base_only} == {"compose.yaml"}
        match = re.fullmatch(
            r"service: base-only  \(line (\d+)\)", headers["service: base-only"]
        )
        assert match is not None
        assert int(match.group(1)) in {f["line"] for f in base_only}
        # The split service really does have findings in both files.
        assert {f["file"] for f in findings if f["service"] == "reverse-proxy"} == {
            "compose.yaml",
            "svc/a.yaml",
        }

    def test_a_service_header_keeps_its_line_in_a_single_file(
        self, project: Path
    ) -> None:
        text = run_cli("compose.yaml", cwd=project).stdout
        assert re.search(r"service: reverse-proxy  \(line \d+\)", text)

    def test_the_last_file_wins(self, project: Path) -> None:
        write(project / "on.yaml", PRIVILEGED)
        write(project / "off.yaml", UNPRIVILEGED)
        on_last = run_cli(
            "-f", "compose.yaml", "-f", "off.yaml", "-f", "on.yaml", cwd=project
        )
        off_last = run_cli(
            "-f", "compose.yaml", "-f", "on.yaml", "-f", "off.yaml", cwd=project
        )
        assert "CL-0002" in on_last.stdout
        assert "CL-0002" not in off_last.stdout

    def test_the_override_and_the_env_list_are_named_and_not_merged(
        self, project: Path
    ) -> None:
        write(project / "compose.override.yml", PRIVILEGED)
        write(project / "extra.yaml", PRIVILEGED)
        write(project / ".env", "COMPOSE_FILE=compose.yaml:extra.yaml\n")
        result = run_cli("-f", "compose.yaml", "-f", "svc/a.yaml", cwd=project)
        assert "CL-0002" not in result.stdout
        assert "compose.override.yml: not merged" in result.stderr
        assert "COMPOSE_FILE was not used" in result.stderr

    def test_the_env_file_beside_the_first_file_supplies_values(
        self, project: Path
    ) -> None:
        write(project / "svc" / "a.yaml", OVERLAY_A + "    privileged: ${P}\n")
        write(project / ".env", "P=true\n")
        write(project / "svc" / ".env", "P=false\n")
        result = run_cli("-f", "compose.yaml", "-f", "svc/a.yaml", cwd=project)
        assert "CL-0002" in result.stdout

    def test_a_single_file_is_linted_without_its_override(self, project: Path) -> None:
        write(project / "compose.override.yml", PRIVILEGED)
        named = run_cli("-f", "compose.yaml", cwd=project)
        positional = run_cli("compose.yaml", cwd=project)
        assert "CL-0002" not in named.stdout
        assert "CL-0002" in positional.stdout

    def test_no_merge_overrides_is_accepted_and_changes_nothing(
        self, project: Path
    ) -> None:
        plain = run_cli("-f", "compose.yaml", "-f", "svc/a.yaml", cwd=project)
        flagged = run_cli(
            "--no-merge-overrides",
            "-f",
            "compose.yaml",
            "-f",
            "svc/a.yaml",
            cwd=project,
        )
        assert flagged.returncode == plain.returncode
        assert flagged.stdout == plain.stdout

    def test_a_positional_file_alongside_is_a_usage_error(self, project: Path) -> None:
        result = run_cli(
            "--format", "json", "-f", "compose.yaml", "svc/a.yaml", cwd=project
        )
        assert result.returncode == 2
        assert "pass one or the other" in result.stderr
        assert json.loads(result.stdout)["findings"] == []

    def test_a_missing_file_fails_the_project_and_is_named(self, project: Path) -> None:
        result = run_cli("-f", "compose.yaml", "-f", "nope.yaml", cwd=project)
        assert result.returncode == 2
        assert "Error: nope.yaml:" in result.stderr
        assert "CL-" not in result.stdout

    def test_a_refused_link_fails_even_with_partial_coverage_allowed(
        self, project: Path, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        """Nothing was graded, so there is nothing for the flag to accept."""
        outside = write(tmp_path_factory.mktemp("outside") / "x.yaml", PRIVILEGED)
        (project / "linked.yaml").symlink_to(outside)
        result = run_cli(
            "--allow-partial-coverage",
            "-f",
            "compose.yaml",
            "-f",
            "linked.yaml",
            cwd=project,
        )
        assert result.returncode == 2
        assert "linked.yaml: not read because it links" in result.stderr
        assert "no Compose file was left to lint" in result.stderr

    def test_the_config_beside_the_first_file_is_used(self, project: Path) -> None:
        write(project / "svc" / "a.yaml", OVERLAY_A + "    privileged: true\n")
        write(
            project / ".compose-lint.yml",
            "rules:\n  CL-0002:\n    enabled: false\n    reason: test\n",
        )
        result = run_cli(
            "--skip-suppressed", "-f", "compose.yaml", "-f", "svc/a.yaml", cwd=project
        )
        assert "CL-0002" not in result.stdout


class TestArgv:
    """`-f` through the shim that makes `check` the default subcommand."""

    @pytest.mark.parametrize(
        ("argv", "command", "files"),
        [
            (["-f", "a.yaml", "-f", "b.yaml"], "check", ["a.yaml", "b.yaml"]),
            (["-fa.yaml", "--file=b.yaml"], "check", ["a.yaml", "b.yaml"]),
            # A file named like a subcommand is the flag's value, not a command.
            (["-f", "fix", "--file", "init"], "check", ["fix", "init"]),
            (["fix", "-f", "a.yaml"], "fix", ["a.yaml"]),
            (["init", "-f", "a.yaml"], "init", ["a.yaml"]),
        ],
    )
    def test_routing(self, argv: list[str], command: str, files: list[str]) -> None:
        parser = cli._build_parser()
        args = parser.parse_args(cli._normalize_argv(argv, cli._value_options(parser)))
        assert args.command == command
        assert args.project_files == files


class TestFix:
    def test_only_the_first_file_is_edited(self, project: Path) -> None:
        write(
            project / "compose.yaml",
            FIXABLE_BASE,
        )
        write(
            project / "svc" / "a.yaml",
            FIXABLE_OVERLAY,
        )
        overlay_before = (project / "svc" / "a.yaml").read_text()
        base_before = (project / "compose.yaml").read_text()
        result = run_cli(
            "fix", "--apply", "-f", "compose.yaml", "-f", "svc/a.yaml", cwd=project
        )
        assert result.returncode == 0, result.stderr
        assert (project / "svc" / "a.yaml").read_text() == overlay_before
        assert (project / "compose.yaml").read_text() != base_before
        assert "svc/a.yaml" in result.stderr

    def test_a_repeated_base_is_still_fixed(self, project: Path) -> None:
        write(
            project / "compose.yaml",
            FIXABLE_BASE,
        )
        before = (project / "compose.yaml").read_text()
        result = run_cli(
            "fix",
            "--apply",
            "-f",
            "compose.yaml",
            "-f",
            "svc/a.yaml",
            "-f",
            "compose.yaml",
            cwd=project,
        )
        assert result.returncode == 0, result.stderr
        assert (project / "compose.yaml").read_text() != before

    def test_other_files_are_named_relative_to_the_working_directory(
        self, project: Path
    ) -> None:
        """A document reached through `extends:` is held by its absolute path,
        and `fix` printed that path while `check` printed the relative one
        for the same file."""
        write(project / "common.yaml", "services:\n  db:\n    image: example/db:1\n")
        write(
            project / "compose.yaml",
            "services:\n  reverse-proxy:\n    image: traefik:v3\n"
            "  db:\n    extends:\n      file: ./common.yaml\n      service: db\n",
        )
        write(project / "svc" / "a.yaml", FIXABLE_OVERLAY)
        result = run_cli("fix", "-f", "compose.yaml", "-f", "svc/a.yaml", cwd=project)
        assert result.returncode == 0, result.stderr
        assert "come from common.yaml, svc/a.yaml; fix by hand there" in result.stderr
        assert "\n  common.yaml line " in result.stderr
        assert "\n  svc/a.yaml line " in result.stderr
        assert str(project) not in result.stderr


class TestInit:
    def test_the_baseline_describes_the_merged_project(self, project: Path) -> None:
        result = run_cli("init", "-f", "compose.yaml", "-f", "svc/a.yaml", cwd=project)
        assert result.returncode == 0, result.stderr
        assert "because -f names them as one project" in result.stderr
        written = (project / ".compose-lint.yml").read_text()
        assert "service-a" in written
        check = run_cli(
            "--fail-on", "low", "-f", "compose.yaml", "-f", "svc/a.yaml", cwd=project
        )
        assert check.returncode == 0, check.stdout

    def test_the_config_lands_beside_the_first_file(self, project: Path) -> None:
        write(project / "proj" / "compose.yaml", BASE)
        result = run_cli(
            "init", "-f", "proj/compose.yaml", "-f", "svc/a.yaml", cwd=project
        )
        assert result.returncode == 0, result.stderr
        assert (project / "proj" / ".compose-lint.yml").is_file()

    def test_neither_a_file_nor_f_is_a_usage_error(self, project: Path) -> None:
        result = run_cli("init", cwd=project)
        assert result.returncode == 2
        assert "init needs a Compose file" in result.stderr

    def test_both_a_file_and_f_is_a_usage_error(self, project: Path) -> None:
        result = run_cli("init", "compose.yaml", "-f", "svc/a.yaml", cwd=project)
        assert result.returncode == 2
        assert "pass one or the other" in result.stderr

    def test_messages_name_the_first_f_file(self, project: Path) -> None:
        missing = run_cli("init", "-f", "nope.yaml", cwd=project)
        assert missing.returncode == 2
        assert "Error: nope.yaml:" in missing.stderr
        write(
            project / "clean.yaml",
            "services:\n  web:\n    image: i@sha256:" + "a" * 64 + "\n"
            "    read_only: true\n    cap_drop: [ALL]\n"
            "    security_opt: [no-new-privileges:true]\n"
            "    mem_limit: 64m\n    cpus: 0.5\n    user: '1000:1000'\n"
            "    pids_limit: 64\n    networks: [n]\nnetworks:\n  n: {}\n",
        )
        clean = run_cli("init", "-f", "clean.yaml", cwd=project)
        assert clean.returncode == 0
        assert "clean.yaml: no findings" in clean.stderr

    def test_a_refused_link_names_the_first_f_file(
        self, project: Path, tmp_path_factory: pytest.TempPathFactory
    ) -> None:
        outside = write(tmp_path_factory.mktemp("outside") / "x.yaml", PRIVILEGED)
        (project / "linked.yaml").symlink_to(outside)
        result = run_cli("init", "-f", "linked.yaml", cwd=project)
        assert result.returncode == 2
        assert "linked.yaml was not linted" in result.stderr

    def test_a_project_of_fragments_is_skipped_by_name(self, project: Path) -> None:
        write(project / "nets.yaml", "networks:\n  n: {}\n")
        write(project / "vols.yaml", "volumes:\n  v: {}\n")
        result = run_cli("init", "-f", "nets.yaml", "-f", "vols.yaml", cwd=project)
        assert result.returncode == 0
        assert result.stderr.startswith("nets.yaml: Skipped")
