"""Files a run finds rather than is given stay inside the project (GHSA-88f4-frh5-gmcr).

A `.compose-lint.yml`, a `compose.yml` and its `compose.override.yml` are all
committed with the change under review. Committed as a symlink to a file
elsewhere on the machine, each was followed: the policy file's parse error
quoted part of the target's line, and a Compose-shaped target's values reached
findings. Now a link whose target leaves its own directory is refused and said,
as a coverage gap for a Compose document and a configuration error for the
policy. A plain path the user typed, and `--config`, are read as given.

Every value here is a synthetic marker.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint import cli

if TYPE_CHECKING:
    from pathlib import Path

MARKER = "cl-link-containment-marker"
CREDENTIALS = f"[default]\nkey_id = {MARKER}\nsecret = {MARKER}\n"
COMPOSE_SHAPED = (
    f"services:\n  web:\n    image: {MARKER}\n    environment:\n      A: {MARKER}\n"
)
PLAIN = "services:\n  web:\n    image: nginx:1.27\n"

pytestmark = pytest.mark.skipif(
    not hasattr(__import__("os"), "symlink"), reason="needs symlinks"
)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


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


def _kinds(doc: dict[str, Any], channel: str = "errors") -> list[tuple[str, str]]:
    return [(entry["kind"], entry["file"]) for entry in doc[channel]]


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    _write(tmp_path / "outside" / "credentials", CREDENTIALS)
    _write(tmp_path / "outside" / "stack.yml", COMPOSE_SHAPED)
    return tmp_path / "outside"


@pytest.fixture
def project(tmp_path: Path) -> Path:
    return tmp_path / "project"


class TestDiscoveredConfig:
    @pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
    def test_a_link_leaving_the_project_is_refused_unread(
        self,
        outside: Path,
        project: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        fmt: str,
    ) -> None:
        _write(project / "compose.yml", PLAIN)
        (project / ".compose-lint.yml").symlink_to(outside / "credentials")
        code, out, err = _run(
            ["--format", fmt, "compose.yml"], project, monkeypatch, capsys
        )
        assert code == 2
        assert MARKER not in out
        assert MARKER not in err
        assert "resolves outside the project directory" in err

    def test_the_second_spelling_is_contained_too(
        self,
        outside: Path,
        project: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(project / "compose.yml", PLAIN)
        (project / ".compose-lint.yaml").symlink_to(outside / "credentials")
        code, out, err = _run(["compose.yml"], project, monkeypatch, capsys)
        assert code == 2
        assert MARKER not in out + err

    def test_a_link_inside_the_project_is_read(
        self,
        project: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(project / "compose.yml", PLAIN)
        _write(
            project / "policy" / "lint.yml", "rules:\n  CL-0007:\n    enabled: false\n"
        )
        (project / ".compose-lint.yml").symlink_to(project / "policy" / "lint.yml")
        code, out, _ = _run(
            ["--format", "json", "compose.yml"], project, monkeypatch, capsys
        )
        doc = json.loads(out)
        assert doc["errors"] == []
        suppressed = {f["rule_id"] for f in doc["findings"] if f["suppressed"]}
        assert "CL-0007" in suppressed

    def test_an_explicit_config_is_read_as_given(
        self,
        tmp_path: Path,
        project: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(project / "compose.yml", PLAIN)
        _write(
            tmp_path / "shared" / "lint.yml", "rules:\n  CL-0007:\n    enabled: false\n"
        )
        (project / "lint.yml").symlink_to(tmp_path / "shared" / "lint.yml")
        code, out, _ = _run(
            ["--format", "json", "--config", "lint.yml", "compose.yml"],
            project,
            monkeypatch,
            capsys,
        )
        doc = json.loads(out)
        assert doc["errors"] == []
        assert "CL-0007" in {f["rule_id"] for f in doc["findings"] if f["suppressed"]}


class TestConfigParseError:
    @pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
    def test_it_names_the_position_and_quotes_nothing(
        self,
        project: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        fmt: str,
    ) -> None:
        """The Compose loader dropped PyYAML's quoted snippet in 0.25.0; the
        policy loader kept it."""
        _write(project / "compose.yml", PLAIN)
        _write(project / ".compose-lint.yml", CREDENTIALS)
        code, out, err = _run(
            ["--format", fmt, "compose.yml"], project, monkeypatch, capsys
        )
        assert code == 2
        assert MARKER not in out + err
        assert "Invalid YAML in config file" in err
        assert "at line 2, column 1" in err


class TestComposeDocuments:
    def test_a_discovered_primary_link_is_a_gap(
        self,
        outside: Path,
        project: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        project.mkdir()
        (project / "compose.yml").symlink_to(outside / "stack.yml")
        code, out, err = _run(["--format", "json"], project, monkeypatch, capsys)
        doc = json.loads(out)
        assert code == 2
        assert MARKER not in out + err
        assert ("coverage_gap", "compose.yml") in _kinds(doc)
        assert "no Compose file was left to lint" in err

    def test_a_named_primary_link_is_a_gap(
        self,
        outside: Path,
        project: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The Action's default list, `pattern:`, `files:` fed a list of changed
        files, and pre-commit all hand the linter paths the checkout chose."""
        project.mkdir()
        (project / "compose.yml").symlink_to(outside / "stack.yml")
        code, out, err = _run(
            ["--format", "sarif", "--", "compose.yml"], project, monkeypatch, capsys
        )
        doc = json.loads(out)
        invocation = doc["runs"][0]["invocations"][0]
        assert code == 2
        assert MARKER not in out + err
        assert invocation["executionSuccessful"] is False
        assert "coverage_gap" in {
            n["descriptor"]["id"] for n in invocation["toolExecutionNotifications"]
        }

    def test_the_other_files_are_still_graded(
        self,
        outside: Path,
        project: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(project / "compose.yaml", "services:\n  db:\n    privileged: true\n")
        (project / "compose.yml").symlink_to(outside / "stack.yml")
        code, out, _ = _run(
            ["--format", "json", "compose.yml", "compose.yaml"],
            project,
            monkeypatch,
            capsys,
        )
        doc = json.loads(out)
        assert code == 2
        assert "CL-0002" in {f["rule_id"] for f in doc["findings"]}
        assert MARKER not in out

    def test_an_override_link_is_a_gap_and_the_base_is_graded(
        self,
        outside: Path,
        project: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(project / "compose.yml", PLAIN)
        (project / "compose.override.yml").symlink_to(outside / "stack.yml")
        code, out, err = _run(
            ["--format", "json", "compose.yml"], project, monkeypatch, capsys
        )
        doc = json.loads(out)
        assert code == 2
        assert MARKER not in out + err
        assert _kinds(doc) == [("coverage_gap", "compose.override.yml")]
        assert doc["findings"]

    def test_allow_partial_coverage_accepts_a_refused_override(
        self,
        outside: Path,
        project: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(project / "compose.yml", PLAIN)
        (project / "compose.override.yml").symlink_to(outside / "stack.yml")
        code, out, _ = _run(
            ["--format", "json", "--allow-partial-coverage", "compose.yml"],
            project,
            monkeypatch,
            capsys,
        )
        doc = json.loads(out)
        assert doc["errors"] == []
        assert _kinds(doc, "warnings") == [("coverage_gap", "compose.override.yml")]
        assert code == 0

    def test_links_inside_their_directory_are_followed(
        self,
        project: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _write(project / "deploy" / "stack.yml", PLAIN)
        _write(
            project / "deploy" / "extra.yml",
            "services:\n  web:\n    ports: ['80:80']\n",
        )
        (project / "deploy" / "compose.yml").symlink_to("stack.yml")
        (project / "deploy" / "compose.override.yml").symlink_to("extra.yml")
        code, out, _ = _run(
            ["--format", "json"], project / "deploy", monkeypatch, capsys
        )
        doc = json.loads(out)
        assert doc["errors"] == []
        assert "CL-0005" in {f["rule_id"] for f in doc["findings"]}

    def test_a_plain_path_outside_is_read_as_given(
        self,
        tmp_path: Path,
        project: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """What the user typed is what they meant; only a link is content
        choosing a target."""
        _write(tmp_path / "elsewhere" / "compose.yml", PLAIN)
        project.mkdir()
        code, out, _ = _run(
            ["--format", "json", "../elsewhere/compose.yml"],
            project,
            monkeypatch,
            capsys,
        )
        assert json.loads(out)["errors"] == []

    @pytest.mark.parametrize("command", ["fix", "init"])
    def test_fix_and_init_refuse_it_too(
        self,
        outside: Path,
        project: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        command: str,
    ) -> None:
        project.mkdir()
        (project / "compose.yml").symlink_to(outside / "stack.yml")
        code, out, err = _run([command, "compose.yml"], project, monkeypatch, capsys)
        assert code == 2
        assert MARKER not in out + err
        assert "resolves outside the project directory" in err
        assert not (project / ".compose-lint.yml").exists()
