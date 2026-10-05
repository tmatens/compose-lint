"""A reference may reach anywhere inside the repository holding the project (ADR-038).

Before this, a reference was contained to the Compose project directory when
spelled with ``..`` and to the run directory when it was a symlink, so the same
``shared/part.yml`` was followed through a committed link and refused as
``../shared/part.yml``. Both now share one root: the nearest directory above
the project holding a ``.git`` entry, the run directory when there is no
repository and it contains the project, and the project directory otherwise.
``.git`` itself is never read.

Every value here is a synthetic marker.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint import cli
from compose_lint._env_file import read_env
from compose_lint._safe_read import OUT_OF_REACH, containment_root, out_of_reach
from compose_lint._service_env import project_relative, resolve_env_files
from compose_lint.parser import load_compose_full

if TYPE_CHECKING:
    from pathlib import Path

MARKER = "cl-repository-reach-marker"
PART = "services:\n  shared:\n    image: nginx:1.27\n    privileged: true\n"
BASE = "services:\n  base:\n    image: nginx:1.27\n    privileged: true\n"
PLAIN = "services:\n  web:\n    image: nginx:1.27\n"


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _repo(tmp_path: Path) -> Path:
    """A repository with a Compose project in a subdirectory and shared files above."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    _write(repo / "shared" / "part.yml", PART)
    _write(repo / "shared" / "base.yml", BASE)
    _write(repo / "shared" / "app.env", f"DB_PASSWORD={MARKER}\n")
    _write(repo / ".env", "TAG=1.27\n")
    _write(tmp_path / "outside" / "part.yml", PART)
    return repo


def _run(
    args: list[str],
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, dict[str, Any], str]:
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("NO_COLOR", "1")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        cli.main(["--format", "json", *args])
    captured = capsys.readouterr()
    code = exc.value.code if isinstance(exc.value.code, int) else 1
    return code, json.loads(captured.out), captured.err


# --- Where the root is ------------------------------------------------------


class TestContainmentRoot:
    def test_the_nearest_git_directory_above_the_project(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path)
        assert containment_root(repo / "svc" / "deep") == repo

    def test_a_git_file_marks_a_worktree_or_submodule(self, tmp_path: Path) -> None:
        repo = tmp_path / "wt"
        _write(repo / ".git", "gitdir: /elsewhere/.git/worktrees/wt\n")
        assert containment_root(repo / "svc") == repo

    def test_the_nearest_marker_wins(self, tmp_path: Path) -> None:
        """A submodule is its own repository, so it does not reach its parent's."""
        outer = _repo(tmp_path)
        _write(outer / "vendor" / "sub" / ".git", "gitdir: ../../.git/modules/sub\n")
        assert (
            containment_root(outer / "vendor" / "sub" / "svc")
            == outer / "vendor" / "sub"
        )

    def test_without_a_repository_the_run_directory_that_contains_the_project(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "tree" / "svc").mkdir(parents=True)
        monkeypatch.chdir(tmp_path / "tree")
        assert containment_root(tmp_path / "tree" / "svc") == tmp_path / "tree"

    def test_a_run_directory_that_does_not_contain_the_project_is_not_used(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "tree" / "svc").mkdir(parents=True)
        (tmp_path / "elsewhere").mkdir()
        monkeypatch.chdir(tmp_path / "elsewhere")
        assert containment_root(tmp_path / "tree" / "svc") == tmp_path / "tree" / "svc"

    def test_the_filesystem_root_is_never_the_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A run from `/` would otherwise reach every file on the machine."""
        (tmp_path / "svc").mkdir()
        monkeypatch.chdir(tmp_path.anchor)
        assert containment_root(tmp_path / "svc") == tmp_path / "svc"

    def test_dot_dot_in_the_given_path_is_folded_before_the_walk(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`../elsewhere` named from inside `project` is not inside `project`."""
        (tmp_path / "project").mkdir()
        (tmp_path / "elsewhere").mkdir()
        monkeypatch.chdir(tmp_path / "project")
        root = containment_root(tmp_path / "project" / ".." / "elsewhere")
        assert root == tmp_path / "elsewhere"


# --- What is followed -------------------------------------------------------


def test_an_include_climbing_to_a_shared_directory_is_merged(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    target = _write(
        repo / "svc" / "compose.yml", "include:\n  - ../shared/part.yml\n" + PLAIN
    )

    loaded = load_compose_full(target)

    assert loaded.gaps == ()
    assert loaded.data["services"]["shared"]["privileged"] is True


def test_an_extends_base_above_the_project_is_merged(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    target = _write(
        repo / "svc" / "compose.yml",
        "services:\n  web:\n    extends:\n      file: ../shared/base.yml\n"
        "      service: base\n",
    )

    loaded = load_compose_full(target)

    assert loaded.gaps == ()
    assert loaded.data["services"]["web"]["privileged"] is True


def test_a_project_directory_above_the_project_is_honoured(tmp_path: Path) -> None:
    """Compose reads that directory's `.env` for the entry, so the root one is."""
    repo = _repo(tmp_path)
    _write(
        repo / "svc" / "sub" / "part.yml",
        "services:\n  part:\n    image: nginx:${TAG:-none}\n",
    )
    target = _write(
        repo / "svc" / "compose.yml",
        "include:\n  - path: sub/part.yml\n    project_directory: ..\n" + PLAIN,
    )

    loaded = load_compose_full(target)

    assert loaded.gaps == ()
    assert loaded.data["services"]["part"]["image"] == "nginx:1.27"


def test_an_env_file_above_the_project_is_read(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    target = _write(
        repo / "svc" / "compose.yml",
        "services:\n  web:\n    image: nginx:1.27\n    env_file: ../shared/app.env\n",
    )

    loaded = load_compose_full(target)
    resolved = resolve_env_files(loaded.data, target.parent)

    assert loaded.data["services"]["web"]["env_file"] == "../shared/app.env"
    assert resolved["web"].unread == ()
    assert [key.key for key in resolved["web"].available] == ["DB_PASSWORD"]


def test_an_inherited_env_file_is_spelled_from_the_project_directory(
    tmp_path: Path,
) -> None:
    """A base at `shared/` writing `./app.env` is read as `../shared/app.env`
    from `svc/`: the merged document stays in Compose's frame, so handing it
    to Compose from the project directory opens the same file."""
    repo = _repo(tmp_path)
    _write(
        repo / "shared" / "with-env.yml",
        "services:\n  base:\n    image: nginx:1.27\n    env_file: ./app.env\n",
    )
    target = _write(
        repo / "svc" / "compose.yml",
        "services:\n  web:\n    extends:\n      file: ../shared/with-env.yml\n"
        "      service: base\n",
    )

    loaded = load_compose_full(target)
    resolved = resolve_env_files(loaded.data, target.parent)

    assert loaded.data["services"]["web"]["env_file"] == "../shared/app.env"
    assert [key.key for key in resolved["web"].available] == ["DB_PASSWORD"]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_a_linked_env_is_read_wherever_the_run_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The link rule used to need the run directory to contain the target."""
    repo = _repo(tmp_path)
    (repo / "svc").mkdir()
    (repo / "svc" / ".env").symlink_to(repo / ".env")
    (tmp_path / "unrelated").mkdir()
    monkeypatch.chdir(tmp_path / "unrelated")

    parsed = read_env(repo / "svc", {"TAG"})

    assert parsed is not None
    assert parsed.values == {"TAG": "1.27"}


def test_the_cli_follows_it_from_the_project_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Run from `svc/`, as a developer does, the repository is still the root."""
    repo = _repo(tmp_path)
    _write(repo / "svc" / "compose.yml", "include:\n  - ../shared/part.yml\n" + PLAIN)

    code, doc, _ = _run(["compose.yml"], repo / "svc", monkeypatch, capsys)

    assert doc["errors"] == []
    assert "CL-0002" in {f["rule_id"] for f in doc["findings"]}
    assert code == 1


# --- What stays a gap -------------------------------------------------------


@pytest.mark.parametrize(
    "reference",
    ["../../outside/part.yml", "/etc/compose/part.yml", "../.git/config"],
)
def test_a_reference_leaving_the_repository_stays_a_gap(
    tmp_path: Path, reference: str
) -> None:
    repo = _repo(tmp_path)
    _write(repo / ".git" / "config", f"[core]\n\tmarker = {MARKER}\n")
    target = _write(
        repo / "svc" / "compose.yml", f"include:\n  - {reference}\n" + PLAIN
    )

    loaded = load_compose_full(target)

    (gap,) = loaded.gaps
    assert "outside the repository" in gap
    assert MARKER not in gap
    assert "shared" not in loaded.data["services"]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_a_link_leaving_the_repository_stays_a_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Even when the run starts above both: the repository is the root, not
    the run directory, once there is one."""
    repo = _repo(tmp_path)
    (repo / "svc").mkdir()
    (repo / "svc" / "linked.yml").symlink_to(tmp_path / "outside" / "part.yml")
    target = _write(repo / "svc" / "compose.yml", "include:\n  - linked.yml\n" + PLAIN)
    monkeypatch.chdir(tmp_path)

    loaded = load_compose_full(target)

    (gap,) = loaded.gaps
    assert OUT_OF_REACH in gap
    assert "shared" not in loaded.data["services"]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_a_link_into_the_git_directory_is_refused(tmp_path: Path) -> None:
    """A checkout writes the job's credential into `.git/config` by default,
    and that directory is the one thing inside a checkout that is not the
    change under review."""
    repo = _repo(tmp_path)
    _write(repo / ".git" / "config", f"[core]\n\tmarker = {MARKER}\n")
    (repo / "svc").mkdir()
    (repo / "svc" / "linked.yml").symlink_to(repo / ".git" / "config")
    target = _write(repo / "svc" / "compose.yml", "include:\n  - linked.yml\n" + PLAIN)

    loaded = load_compose_full(target)

    (gap,) = loaded.gaps
    assert OUT_OF_REACH in gap
    assert MARKER not in gap
    assert out_of_reach(repo / "svc" / "linked.yml", repo / "svc")


def test_a_path_naming_a_git_directory_leaves_lexically() -> None:
    assert project_relative(".git/config") is None
    assert project_relative("../.git/config", ("svc",)) is None
    assert project_relative("sub/.git/x", ("svc",)) is None
    assert project_relative("gitless/x", ("svc",)) == ["svc", "gitless", "x"]


def test_an_env_file_leaving_the_repository_is_still_not_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path)
    _write(tmp_path / "outside" / "db.env", f"DB_PASSWORD={MARKER}\n")
    _write(
        repo / "svc" / "compose.yml",
        "services:\n  web:\n    image: nginx:1.27\n"
        "    env_file: ../../outside/db.env\n",
    )

    code, doc, err = _run(["svc/compose.yml"], repo, monkeypatch, capsys)

    (warning,) = [w for w in doc["warnings"] if w["kind"] == "unread_input"]
    assert "outside the repository" in warning["message"]
    assert MARKER not in json.dumps(doc) + err
    assert code == 0


def test_the_projects_own_unreadable_env_is_reported_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The project directory is no longer the containment root, and the
    loader's "included file's `.env` was not read" gap must still skip the
    project's own, which file selection already reports."""
    repo = _repo(tmp_path)
    _write(
        repo / "svc" / "compose.yml",
        "services:\n  web:\n    image: nginx:${TAG:-none}\n",
    )
    (repo / "svc" / ".env").write_bytes(b"TAG=\xff\xfe\n")

    code, doc, _ = _run(["svc/compose.yml"], repo, monkeypatch, capsys)

    env_gaps = [e for e in doc["errors"] if e["file"].endswith(".env")]
    assert len(env_gaps) == 1
    assert code == 2
