"""Where an implicit run finds its config (ADR-039).

Compose takes the first compose file's directory as the project directory, so
a config written beside the compose file is the one its author expects to be
in force — including when CI or pre-commit runs from the repository root. The
working directory stays the fallback so a single root config keeps covering
projects with none of their own.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests._cli_env import cli_env

REPO_ROOT = Path(__file__).resolve().parent.parent

_INSECURE = "services:\n  app:\n    image: myapp:1.0\n    privileged: true\n"
_DISABLE_0002 = 'rules:\n  CL-0002:\n    enabled: false\n    reason: "test"\n'
_DISABLE_0019 = 'rules:\n  CL-0019:\n    enabled: false\n    reason: "test"\n'


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "compose_lint", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=cli_env(PYTHONPATH=str(REPO_ROOT / "src"), NO_COLOR="1"),
        timeout=120,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repository root with one Compose project in ``app/``."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "docker-compose.yml").write_text(_INSECURE, encoding="utf-8")
    return tmp_path


def test_a_config_beside_the_compose_file_is_read_from_the_root(repo: Path) -> None:
    (repo / "app" / ".compose-lint.yml").write_text(_DISABLE_0002, encoding="utf-8")
    proc = _run("check", "app/docker-compose.yml", cwd=repo)
    assert "config: app/.compose-lint.yml" in proc.stdout
    report = _run("check", "--format", "json", "app/docker-compose.yml", cwd=repo)
    (privileged,) = [
        f for f in json.loads(report.stdout)["findings"] if f["rule_id"] == "CL-0002"
    ]
    assert privileged["suppressed"] is True


def test_the_working_directory_config_is_the_fallback(repo: Path) -> None:
    (repo / ".compose-lint.yml").write_text(_DISABLE_0002, encoding="utf-8")
    proc = _run("check", "app/docker-compose.yml", cwd=repo)
    assert "config: .compose-lint.yml" in proc.stdout


def test_the_compose_files_config_wins_over_the_working_directorys(
    repo: Path,
) -> None:
    (repo / ".compose-lint.yml").write_text(_DISABLE_0019, encoding="utf-8")
    (repo / "app" / ".compose-lint.yml").write_text(_DISABLE_0002, encoding="utf-8")
    proc = _run("check", "--format", "json", "app/docker-compose.yml", cwd=repo)
    suppressed = {
        f["rule_id"]: f.get("suppressed", False)
        for f in json.loads(proc.stdout)["findings"]
    }
    assert suppressed.get("CL-0002") is True
    assert suppressed.get("CL-0019") is False


def test_the_suppression_reason_names_the_config_it_came_from(repo: Path) -> None:
    """With no reason written, the text report says which file disabled it."""
    (repo / "app" / ".compose-lint.yml").write_text(
        "rules:\n  CL-0002:\n    enabled: false\n", encoding="utf-8"
    )
    proc = _run("check", "app/docker-compose.yml", cwd=repo)
    assert "disabled in app/.compose-lint.yml" in proc.stdout


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_a_config_beside_the_compose_file_is_contained_to_its_directory(
    repo: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    outside = tmp_path_factory.mktemp("elsewhere") / "policy.yml"
    outside.write_text(_DISABLE_0002, encoding="utf-8")
    try:
        (repo / "app" / ".compose-lint.yml").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    proc = _run("check", "app/docker-compose.yml", cwd=repo)
    assert proc.returncode == 2
    assert "Cannot read config file" in proc.stderr
    assert "outside" in proc.stderr


def test_a_failing_run_with_no_config_adds_no_note(repo: Path) -> None:
    """The banner says ``config: none``; a first run has nothing to act on."""
    for args in (
        ("check", "app/docker-compose.yml"),
        ("fix", "app/docker-compose.yml"),
    ):
        proc = _run(*args, cwd=repo)
        assert "found in" not in proc.stderr, args
        assert "suppressions are in effect" not in proc.stderr, args


def test_a_sibling_projects_config_is_read_without_a_repository(
    tmp_path: Path,
) -> None:
    """``../other/compose.yml`` from a directory with no ``.git`` above.

    Containment decided from lexical paths took ``/cwd/../other`` to be inside
    the working directory, then refused the config as resolving outside it.
    """
    (tmp_path / "cwd").mkdir()
    (tmp_path / "other").mkdir()
    (tmp_path / "other" / "docker-compose.yml").write_text(_INSECURE, encoding="utf-8")
    (tmp_path / "other" / ".compose-lint.yml").write_text(
        _DISABLE_0002, encoding="utf-8"
    )
    proc = _run("check", "../other/docker-compose.yml", cwd=tmp_path / "cwd")
    # The config disables the only HIGH, so a config that was read passes.
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "config: ../other/.compose-lint.yml" in proc.stdout


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_a_config_under_a_linked_project_directory_is_read(tmp_path: Path) -> None:
    """The Compose file is read through the link; so is the config beside it."""
    (tmp_path / "cwd").mkdir()
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "docker-compose.yml").write_text(
        _INSECURE, encoding="utf-8"
    )
    (tmp_path / "elsewhere" / ".compose-lint.yml").write_text(
        _DISABLE_0002, encoding="utf-8"
    )
    try:
        (tmp_path / "cwd" / "link").symlink_to(tmp_path / "elsewhere")
    except OSError:
        pytest.skip("symlinks unavailable")
    proc = _run("check", "link/docker-compose.yml", cwd=tmp_path / "cwd")
    # The config disables the only HIGH, so a config that was read passes.
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "config: link/.compose-lint.yml" in proc.stdout


# --- init writes where check reads -----------------------------------------


def test_init_writes_the_baseline_beside_the_compose_file(repo: Path) -> None:
    proc = _run("init", "app/docker-compose.yml", cwd=repo)
    assert proc.returncode == 0, proc.stderr
    assert (repo / "app" / ".compose-lint.yml").is_file()
    assert not (repo / ".compose-lint.yml").exists()
    after = _run("check", "app/docker-compose.yml", cwd=repo)
    assert after.returncode == 0, after.stdout + after.stderr
    assert "config: app/.compose-lint.yml" in after.stdout


def test_init_says_when_its_baseline_replaces_the_root_config(repo: Path) -> None:
    (repo / ".compose-lint.yml").write_text(_DISABLE_0019, encoding="utf-8")
    proc = _run("init", "app/docker-compose.yml", cwd=repo)
    assert proc.returncode == 0, proc.stderr
    assert (
        "note: app/.compose-lint.yml will be used for app/docker-compose.yml "
        "instead of .compose-lint.yml"
    ) in proc.stderr


def test_init_adds_no_note_when_nothing_is_replaced(repo: Path) -> None:
    proc = _run("init", "app/docker-compose.yml", cwd=repo)
    assert "note: app/.compose-lint.yml" not in proc.stderr


def test_init_treats_either_spelling_beside_the_file_as_existing(repo: Path) -> None:
    (repo / "app" / ".compose-lint.yaml").write_text(_DISABLE_0002, encoding="utf-8")
    proc = _run("init", "app/docker-compose.yml", cwd=repo)
    assert proc.returncode == 2
    assert "app/.compose-lint.yaml already exists" in proc.stderr.replace("\\", "/")
    assert not (repo / "app" / ".compose-lint.yml").exists()


def test_init_output_flag_still_wins(repo: Path) -> None:
    proc = _run("init", "app/docker-compose.yml", "-o", "policy.yml", cwd=repo)
    assert proc.returncode == 0, proc.stderr
    assert (repo / "policy.yml").is_file()
    assert not (repo / "app" / ".compose-lint.yml").exists()
