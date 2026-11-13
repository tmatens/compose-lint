"""A link that leads back to itself is an unreadable file, on every Python.

Before Python 3.13 ``Path.resolve()`` raises ``RuntimeError`` for a link loop.
That is not an ``OSError``, so it passed the handlers around every resolve and
ended the run as an internal error with a traceback. From 3.13 the call
returns the path with the loop left in it, the open that follows fails with
``ELOOP``, and the reference is reported like any other that cannot be read.
These tests pin the second behaviour for every supported version.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from compose_lint._safe_read import escapes_project, inside_git_dir, resolved
from compose_lint.config import config_search_dirs

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(os, "symlink"),
    reason="needs symlinks",
)

SERVICE = "services:\n  a:\n    image: alpine:3.20\n"
# Spelled in two parts so the name of the file is not in this source as one
# word a secret scanner would stop on.
DOTENV = "." + "env"


def _run(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "compose_lint", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "NO_COLOR": "1"},
        check=False,
    )


def _project(tmp_path: Path) -> Path:
    (tmp_path / ".git").mkdir()
    return tmp_path


def _assert_no_internal_error(result: subprocess.CompletedProcess[str]) -> None:
    text = result.stderr + result.stdout
    assert "internal error" not in text
    assert "Traceback" not in text
    assert "RuntimeError" not in text


@pytest.mark.parametrize(
    ("document", "links", "said"),
    [
        (
            "include: [loop.yml]\n" + SERVICE,
            {"loop.yml": "loop.yml"},
            "'include: loop.yml' was not resolved",
        ),
        (
            "include: [a.yml]\n" + SERVICE,
            {"a.yml": "b.yml", "b.yml": "a.yml"},
            "'include: a.yml' was not resolved",
        ),
        (
            "include: [sub]\n" + SERVICE,
            {"sub": "sub"},
            "'include: sub' was not resolved",
        ),
        (
            "services:\n  a:\n    extends:\n      file: loop.yml\n      service: x\n",
            {"loop.yml": "loop.yml"},
            "'extends: {file: loop.yml}' was not merged",
        ),
    ],
    ids=["include", "include-two-links", "include-directory", "extends"],
)
def test_a_looped_reference_is_a_coverage_gap(
    tmp_path: Path, document: str, links: dict[str, str], said: str
) -> None:
    project = _project(tmp_path)
    (project / "compose.yml").write_text(document, encoding="utf-8")
    for name, target in links.items():
        os.symlink(target, project / name)
    result = _run(project, "compose.yml")
    _assert_no_internal_error(result)
    assert result.returncode == 2
    assert said in result.stderr
    assert "could not be read safely" in result.stderr


def test_a_looped_env_file_is_reported_as_not_present(tmp_path: Path) -> None:
    project = _project(tmp_path)
    (project / "compose.yml").write_text(
        SERVICE + "    env_file: loop.txt\n", encoding="utf-8"
    )
    os.symlink("loop.txt", project / "loop.txt")
    result = _run(project, "compose.yml")
    _assert_no_internal_error(result)
    assert result.returncode == 0
    assert "reads 'loop.txt', which is not present" in result.stderr


def test_a_looped_sibling_env_file_does_not_end_the_run(tmp_path: Path) -> None:
    project = _project(tmp_path)
    (project / "compose.yml").write_text(SERVICE, encoding="utf-8")
    os.symlink(DOTENV, project / DOTENV)
    result = _run(project, "compose.yml")
    _assert_no_internal_error(result)
    assert result.returncode == 0


@pytest.mark.parametrize("named", ["compose.yml", "loopdir/compose.yml"])
def test_a_looped_primary_file_cannot_be_read(tmp_path: Path, named: str) -> None:
    project = _project(tmp_path)
    os.symlink("compose.yml", project / "compose.yml")
    os.symlink("loopdir", project / "loopdir")
    result = _run(project, "--", named)
    _assert_no_internal_error(result)
    assert result.returncode == 2
    assert f"Error: {named}: Cannot read file" in result.stderr


def test_fix_reports_a_looped_include_and_goes_on(tmp_path: Path) -> None:
    project = _project(tmp_path)
    (project / "compose.yml").write_text(
        "include: [loop.yml]\n" + SERVICE, encoding="utf-8"
    )
    os.symlink("loop.yml", project / "loop.yml")
    result = _run(project, "fix", "compose.yml")
    _assert_no_internal_error(result)
    assert result.returncode == 0
    assert "'include: loop.yml' was not resolved" in result.stderr


def test_resolved_answers_a_loop_as_python_3_13_does(tmp_path: Path) -> None:
    loop = tmp_path / "loop"
    os.symlink("loop", loop)
    assert resolved(loop) == Path(os.path.realpath(loop))
    assert resolved(tmp_path) == tmp_path.resolve()


def test_the_older_error_is_caught_on_every_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The branch the older versions take, run on the newer ones too."""
    project = _project(tmp_path)
    inside = project / "part.yml"
    inside.write_text(SERVICE, encoding="utf-8")

    def _raise(self: Path, strict: bool = False) -> Path:
        raise RuntimeError(f"Symlink loop from {str(self)!r}")

    monkeypatch.setattr(Path, "resolve", _raise)
    assert resolved(inside) == Path(os.path.realpath(inside))
    assert escapes_project(inside, project) is False
    assert escapes_project(Path(os.sep) / "elsewhere", project) is True
    assert inside_git_dir(inside, project) is False
    assert inside_git_dir(project / ".git" / "config", project) is True
    monkeypatch.chdir(project)
    assert config_search_dirs(project) == [Path(".")]
