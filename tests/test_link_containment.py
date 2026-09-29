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
import os
from pathlib import Path
from typing import Any

import pytest

from compose_lint import cli

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
        assert "resolves outside both the project directory" in err

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
        assert "links to a file outside both its own directory" in err
        assert not (project / ".compose-lint.yml").exists()


PRIVILEGED = "services:\n  web:\n    image: nginx:1.27\n    privileged: true\n"


class TestLinkRoot:
    """A linked Compose file is followed while its target stays inside the
    directory the run started in: in CI that is the checkout, whose content the
    change under review can already see."""

    def test_a_shared_file_linked_into_a_monorepo_is_graded(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        repo = tmp_path / "repo"
        _write(repo / "shared" / "compose.yml", PRIVILEGED)
        link = repo / "services" / "foo" / "compose.yml"
        link.parent.mkdir(parents=True)
        link.symlink_to(Path("..", "..", "shared", "compose.yml"))
        for path in ("services/foo/compose.yml", "./services/foo/compose.yml"):
            code, out, _ = _run(
                ["--format", "json", "--", path], repo, monkeypatch, capsys
            )
            doc = json.loads(out)
            assert code == 1
            assert doc["errors"] == []
            assert "CL-0002" in {f["rule_id"] for f in doc["findings"]}

    def test_run_from_the_link_directory_it_is_still_refused(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Neither root contains the target when the run starts beside the link."""
        repo = tmp_path / "repo"
        _write(repo / "shared" / "x.yml", PRIVILEGED)
        (repo / "app").mkdir()
        (repo / "app" / "compose.yml").symlink_to(Path("..", "shared", "x.yml"))
        code, _, err = _run([], repo / "app", monkeypatch, capsys)
        assert code == 2
        assert "Run compose-lint from a directory that contains the target" in err

    def test_a_chain_that_leaves_the_run_directory_is_refused(
        self,
        outside: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The first hop stays in the checkout; the final target does not."""
        repo = tmp_path / "repo"
        (repo / "hop").mkdir(parents=True)
        (repo / "hop" / "link.yml").symlink_to(outside / "stack.yml")
        (repo / "app").mkdir()
        (repo / "app" / "compose.yml").symlink_to(Path("..", "hop", "link.yml"))
        code, out, err = _run(
            ["--format", "json", "--", "app/compose.yml"], repo, monkeypatch, capsys
        )
        assert code == 2
        assert MARKER not in out + err
        assert ("coverage_gap", "app/compose.yml") in _kinds(json.loads(out))

    def test_the_targets_references_resolve_beside_the_link(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Compose takes the project directory from the path as given, so the
        linked file's `env_file:` is read from the link's directory, not the
        target's (measured with Compose 5.5.0)."""
        repo = tmp_path / "repo"
        _write(
            repo / "shared" / "x.yml",
            "services:\n  web:\n    image: nginx:1.27\n    env_file: vars.env\n",
        )
        _write(repo / "shared" / "vars.env", "SHARED_SIDE_PASSWORD=placeholder-1\n")
        _write(repo / "app" / "vars.env", "APP_SIDE_PASSWORD=placeholder-2\n")
        (repo / "app" / "compose.yml").symlink_to(Path("..", "shared", "x.yml"))
        _, out, _ = _run(
            ["--format", "json", "--", "app/compose.yml"], repo, monkeypatch, capsys
        )
        messages = " ".join(f["message"] for f in json.loads(out)["findings"])
        assert "APP_SIDE_PASSWORD" in messages
        assert "SHARED_SIDE_PASSWORD" not in messages


PRIV_BY_ENV = (
    "services:\n  web:\n    image: nginx:1.27\n    privileged: ${PRIV:-false}\n"
)


def _link(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(Path(os.path.relpath(target, link.parent)))


class TestOneLinkRuleAtEveryReadSite:
    """Every file a run opens follows a link while its target stays inside the
    directory the run started in, the same rule a linked Compose file already
    had. Compose follows all of these (measured with Compose 5.5.0); each site
    used to pick its own root, so the `.env` beside a followed Compose file
    could be refused for the same link."""

    def _lint(
        self,
        repo: Path,
        cwd: Path,
        path: str,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> tuple[int, dict[str, Any]]:
        code, out, _ = _run(["--format", "json", "--", path], cwd, monkeypatch, capsys)
        return code, json.loads(out)

    def _rules(self, doc: dict[str, Any]) -> set[str]:
        return {f["rule_id"] for f in doc["findings"]}

    def test_a_linked_env_is_read(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        repo = tmp_path / "repo"
        _write(repo / ".env", "PRIV=true\n")
        _write(repo / "svc" / "compose.yml", PRIV_BY_ENV)
        _link(repo / "svc" / ".env", repo / ".env")
        code, doc = self._lint(repo, repo, "svc/compose.yml", monkeypatch, capsys)
        assert doc["errors"] == []
        assert "CL-0002" in self._rules(doc)
        assert code == 1

    def test_run_beside_the_link_the_env_is_still_refused(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """From `svc/` the target is outside both roots: a gap, as before."""
        repo = tmp_path / "repo"
        _write(repo / ".env", "PRIV=true\n")
        _write(repo / "svc" / "compose.yml", PRIV_BY_ENV)
        _link(repo / "svc" / ".env", repo / ".env")
        code, doc = self._lint(repo, repo / "svc", "compose.yml", monkeypatch, capsys)
        assert ("coverage_gap", ".env") in _kinds(doc)
        assert "CL-0002" not in self._rules(doc)
        assert code == 2

    def test_a_linked_compose_file_entry_is_merged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        repo = tmp_path / "repo"
        _write(repo / "svc" / "compose.yml", PLAIN)
        _write(repo / "svc" / ".env", "COMPOSE_FILE=compose.yml:extra.yml\n")
        _write(repo / "shared" / "extra.yml", PRIVILEGED)
        _link(repo / "svc" / "extra.yml", repo / "shared" / "extra.yml")
        code, doc = self._lint(repo, repo, "svc/compose.yml", monkeypatch, capsys)
        assert doc["errors"] == []
        assert "CL-0002" in self._rules(doc)
        assert code == 1

    def test_a_linked_include_target_is_merged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        repo = tmp_path / "repo"
        _write(
            repo / "svc" / "compose.yml",
            "include:\n  - common.yml\nservices:\n  app:\n    image: nginx:1.27\n",
        )
        _write(repo / "shared" / "common.yml", PRIVILEGED)
        _link(repo / "svc" / "common.yml", repo / "shared" / "common.yml")
        code, doc = self._lint(repo, repo, "svc/compose.yml", monkeypatch, capsys)
        assert doc["errors"] == []
        assert "CL-0002" in self._rules(doc)
        assert code == 1

    def test_a_linked_extends_base_is_merged(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        repo = tmp_path / "repo"
        _write(
            repo / "svc" / "compose.yml",
            "services:\n  app:\n    extends:\n      file: base.yml\n"
            "      service: web\n",
        )
        _write(repo / "shared" / "base.yml", PRIVILEGED)
        _link(repo / "svc" / "base.yml", repo / "shared" / "base.yml")
        code, doc = self._lint(repo, repo, "svc/compose.yml", monkeypatch, capsys)
        assert doc["errors"] == []
        assert "CL-0002" in self._rules(doc)
        assert code == 1

    def test_a_linked_env_file_is_read(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        repo = tmp_path / "repo"
        _write(
            repo / "svc" / "compose.yml",
            "services:\n  web:\n    image: nginx:1.27\n    env_file: app.env\n",
        )
        _write(repo / "shared" / "app.env", "DB_PASSWORD=placeholder\n")
        _link(repo / "svc" / "app.env", repo / "shared" / "app.env")
        _, doc = self._lint(repo, repo, "svc/compose.yml", monkeypatch, capsys)
        assert doc["warnings"] == []
        assert "CL-0020" in self._rules(doc)

    def test_a_linked_project_directory_is_used(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The named directory's `.env` supplies the included file's values."""
        repo = tmp_path / "repo"
        _write(
            repo / "svc" / "compose.yml",
            "include:\n  - path: parts/inc.yml\n    project_directory: lib\n"
            "services:\n  app:\n    image: nginx:1.27\n",
        )
        _write(repo / "svc" / "parts" / "inc.yml", PRIV_BY_ENV)
        _write(repo / "shared" / "lib" / ".env", "PRIV=true\n")
        _link(repo / "svc" / "lib", repo / "shared" / "lib")
        code, doc = self._lint(repo, repo, "svc/compose.yml", monkeypatch, capsys)
        assert doc["errors"] == []
        assert "CL-0002" in self._rules(doc)
        assert code == 1

    @pytest.mark.parametrize("site", ["env", "include", "compose_file"])
    def test_a_target_outside_the_run_directory_is_still_refused(
        self,
        site: str,
        outside: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The case containment exists for, at each site: run from the repo, a
        link out of it is refused and nothing it holds reaches the report."""
        repo = tmp_path / "repo"
        _write(outside / "values.env", f"IMG={MARKER}\n")
        compose = repo / "svc" / "compose.yml"
        if site == "env":
            _write(compose, "services:\n  web:\n    image: ${IMG:-nginx:1.27}\n")
            _link(repo / "svc" / ".env", outside / "values.env")
        elif site == "include":
            _write(compose, "include:\n  - stack.yml\n" + PLAIN)
            _link(repo / "svc" / "stack.yml", outside / "stack.yml")
        else:
            _write(compose, PLAIN)
            _write(repo / "svc" / ".env", "COMPOSE_FILE=compose.yml:stack.yml\n")
            _link(repo / "svc" / "stack.yml", outside / "stack.yml")
        code, out, err = _run(
            ["--format", "json", "--", "svc/compose.yml"], repo, monkeypatch, capsys
        )
        assert MARKER not in out + err
        assert "coverage_gap" in {kind for kind, _ in _kinds(json.loads(out))}
        assert code == 2
