"""`check --output PATH`: the report as one file, written without trusting
what is already at the path.

The option exists for the GitHub Action (GHSA-r3vf-vcmg-vp42,
GHSA-r827-h7r9-j3g6). There the workflow fixes the path and a pull request
decides what the checkout holds at it, so every refusal below is a shape a
pull request can commit: a directory, a link, a link in the directory above.
"""

from __future__ import annotations

import json
import os
import stat
from typing import TYPE_CHECKING

import pytest

from compose_lint import cli

if TYPE_CHECKING:
    from pathlib import Path

_INSECURE = "services:\n  web:\n    image: nginx:latest\n    privileged: true\n"
_MARKER = "cl-output-forged"

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX links and modes")
not_root = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root writes into a read-only directory",
)


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A checkout holding one Compose file, with the run started inside it."""
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    (root / "compose.yml").write_text(_INSECURE, encoding="utf-8")
    monkeypatch.chdir(root)
    return root


def _check(*argv: str) -> int:
    with pytest.raises(SystemExit) as stop:
        cli.main(["check", *argv])
    code = stop.value.code
    assert isinstance(code, int)
    return code


def _stdout_of(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = _check(*argv)
    return code, capsys.readouterr().out


# --- the write ---------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
def test_the_file_holds_exactly_what_stdout_would(
    project: Path, capsys: pytest.CaptureFixture[str], fmt: str
) -> None:
    expected_code, expected = _stdout_of(capsys, "--format", fmt, "compose.yml")

    code, out = _stdout_of(capsys, "--format", fmt, "-o", "report.out", "compose.yml")

    assert code == expected_code == 1
    assert out == "", "the report goes to the file instead of stdout"
    assert (project / "report.out").read_text(encoding="utf-8") == expected


def test_the_exit_code_is_still_the_verdict(project: Path) -> None:
    assert _check("--format", "json", "--output", "r.json", "compose.yml") == 1
    assert json.loads((project / "r.json").read_text(encoding="utf-8"))["findings"]

    (project / "compose.yml").write_text(
        "services:\n  web:\n    image: nginx:1.27\n", encoding="utf-8"
    )
    assert _check("--format", "json", "--output", "r.json", "compose.yml") == 0
    assert json.loads((project / "r.json").read_text(encoding="utf-8"))["findings"]


def test_a_missing_parent_directory_is_created(project: Path) -> None:
    code = _check("--format", "sarif", "-o", "reports/new dir/r.sarif", "compose.yml")
    assert code == 1
    written = project / "reports" / "new dir" / "r.sarif"
    assert json.loads(written.read_text(encoding="utf-8"))["version"] == "2.1.0"


@posix_only
def test_a_new_report_is_world_readable(project: Path) -> None:
    _check("--format", "sarif", "-o", "r.sarif", "compose.yml")
    assert stat.S_IMODE((project / "r.sarif").stat().st_mode) == 0o644


def test_an_existing_report_is_replaced_whole(project: Path) -> None:
    """A swap, not a rewrite in place: the old file is never truncated."""
    target = project / "r.sarif"
    target.write_text("PREVIOUS", encoding="utf-8")
    before = target.stat().st_ino

    assert _check("--format", "sarif", "-o", "r.sarif", "compose.yml") == 1

    assert json.loads(target.read_text(encoding="utf-8"))["version"] == "2.1.0"
    if os.name != "nt":
        assert target.stat().st_ino != before


def test_a_run_with_nothing_to_lint_writes_its_envelope(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 2 before any file is graded still leaves the machine-readable
    reason, and it goes where the report was asked to go."""
    (project / "compose.yml").unlink()
    code, out = _stdout_of(capsys, "--format", "json", "-o", "r.json")
    assert code == 2
    assert out == ""
    document = json.loads((project / "r.json").read_text(encoding="utf-8"))
    assert document["errors"]


def test_an_internal_error_leaves_its_envelope_in_the_file(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(cli, "run_rules", boom)
    code, out = _stdout_of(capsys, "--format", "json", "-o", "r.json", "compose.yml")
    assert code == 2
    assert out == ""
    document = json.loads((project / "r.json").read_text(encoding="utf-8"))
    assert "internal error" in document["errors"][0]["message"]


def test_the_root_is_the_repository_not_the_run_directory(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Started in a subdirectory, a path elsewhere in the same checkout is
    still inside what the run may reach."""
    sub = project / "app"
    sub.mkdir()
    (sub / "compose.yml").write_text(_INSECURE, encoding="utf-8")
    monkeypatch.chdir(sub)
    assert _check("--format", "sarif", "-o", "../r.sarif", "compose.yml") == 1
    assert (project / "r.sarif").is_file()


# --- refusals ----------------------------------------------------------------


def _refused(capsys: pytest.CaptureFixture[str], written: str, *extra: str) -> str:
    """Run with ``--output written``; assert a usage error naming it as typed."""
    capsys.readouterr()
    code = _check("--format", "sarif", "--output", written, *extra, "compose.yml")
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert f"Error: --output {written}: " in captured.err
    assert "no report written" in captured.err
    return captured.err


def test_a_directory_at_the_path_is_refused(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Moved "to" a directory, a report lands inside it, beside whatever else
    is there, and the path itself is still the directory."""
    target = project / "r.sarif"
    target.mkdir()
    (target / "forged.sarif").write_text("{}", encoding="utf-8")

    err = _refused(capsys, "r.sarif")

    assert "not a regular file" in err
    assert [p.name for p in target.iterdir()] == ["forged.sarif"]


@posix_only
@pytest.mark.parametrize("kind", ["file", "directory", "dangling"])
def test_a_link_at_the_path_is_refused(
    project: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    """Not followed, and not replaced either: the link is the checkout's."""
    victim = project / "victim"
    if kind == "file":
        victim.write_text("keep", encoding="utf-8")
    elif kind == "directory":
        victim.mkdir()
    (project / "r.sarif").symlink_to("victim")

    err = _refused(capsys, "r.sarif")

    assert "symbolic link" in err
    assert (project / "r.sarif").is_symlink()
    if kind == "file":
        assert victim.read_text(encoding="utf-8") == "keep"
    elif kind == "directory":
        assert list(victim.iterdir()) == []
    else:
        assert not victim.exists()


@posix_only
def test_a_fifo_at_the_path_is_refused(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    os.mkfifo(project / "r.sarif")
    assert "not a regular file" in _refused(capsys, "r.sarif")


@posix_only
def test_a_file_with_a_second_name_is_refused(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / "one").write_text("shared", encoding="utf-8")
    os.link(project / "one", project / "r.sarif")
    assert "hard links" in _refused(capsys, "r.sarif")
    assert (project / "one").read_text(encoding="utf-8") == "shared"


@posix_only
@not_root
def test_a_read_only_file_is_refused(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = project / "r.sarif"
    target.write_text("keep", encoding="utf-8")
    target.chmod(0o444)
    assert "not writable" in _refused(capsys, "r.sarif")
    assert target.read_text(encoding="utf-8") == "keep"


def test_a_path_outside_the_repository_is_refused(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    for written in (str(outside / "r.sarif"), "../elsewhere/r.sarif"):
        assert "outside the repository" in _refused(capsys, written)
    assert list(outside.iterdir()) == []


@posix_only
def test_a_linked_directory_leading_out_is_refused(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`out/r.sarif` is spelled like a path in the checkout; `out` is a
    committed link to somewhere that is not."""
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (project / "out").symlink_to(outside, target_is_directory=True)

    assert "outside the repository" in _refused(capsys, "out/r.sarif")
    assert "outside the repository" in _refused(capsys, "out/new/r.sarif")
    assert list(outside.iterdir()) == []


def test_the_git_directory_is_refused(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert ".git" in _refused(capsys, ".git/r.sarif")
    assert list((project / ".git").iterdir()) == []


@pytest.mark.parametrize("written", ["..", ".", "reports/.."])
def test_a_path_that_names_no_file_is_refused(
    project: Path, capsys: pytest.CaptureFixture[str], written: str
) -> None:
    assert "not a file path" in _refused(capsys, written)


@posix_only
def test_a_directory_that_cannot_be_resolved_is_refused(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / "loop").symlink_to("loop")
    _refused(capsys, "loop/r.sarif")


def test_an_input_of_the_run_is_refused(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`init -o` refuses the same thing: the report would replace the file.
    That covers a document `include:` brought in, and the config."""
    included = project / "extra.yml"
    included_text = "services:\n  db:\n    image: postgres:17\n"
    included.write_text(included_text, encoding="utf-8")
    main = "include:\n  - extra.yml\n" + _INSECURE
    (project / "compose.yml").write_text(main, encoding="utf-8")
    config = project / ".compose-lint.yml"
    config.write_text("rules: {}\n", encoding="utf-8")

    for written in ("compose.yml", "extra.yml", ".compose-lint.yml"):
        assert "one of the files this run read" in _refused(capsys, written)

    assert (project / "compose.yml").read_text(encoding="utf-8") == main
    assert included.read_text(encoding="utf-8") == included_text
    assert config.read_text(encoding="utf-8") == "rules: {}\n"


def test_explain_has_no_file_form(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as stop:
        cli.main(["check", "--explain", "CL-0001", "-o", "doc.md"])
    assert stop.value.code == 2
    assert "--explain cannot be combined with --output" in capsys.readouterr().err
    assert not (project / "doc.md").exists()


@posix_only
@not_root
@pytest.mark.parametrize("name", [f"##[warning]{_MARKER}", f"d\n::warning::{_MARKER}"])
def test_a_failed_write_names_the_path_as_typed(
    project: Path, capsys: pytest.CaptureFixture[str], name: str
) -> None:
    """The directory's real name is the checkout's to choose, and a CI log
    reads this line. Only the spelling the user gave is printed, with the
    condition; the resolved directory and the scratch file are not."""
    named = project / name
    named.mkdir()
    (project / "out").symlink_to(name, target_is_directory=True)
    named.chmod(0o555)
    try:
        err = _refused(capsys, "out/r.sarif")
    finally:
        named.chmod(0o755)

    assert _MARKER not in err
    assert ".tmp" not in err
    assert list(named.iterdir()) == []


def test_a_usage_error_writes_no_file(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Nothing was printed to stdout, so there is no report to put in a file;
    an empty one would read as a clean scan."""
    with pytest.raises(SystemExit) as stop:
        cli.main(["check", "-o", "r.sarif", "--fail-on", "nope", "compose.yml"])
    assert stop.value.code == 2
    assert not (project / "r.sarif").exists()
