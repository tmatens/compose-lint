"""`fix` names each finding it leaves for the user, with the fix to make.

A count ("1 finding(s) need manual review") read as if no fix were known, and
sent the user back to `check` to learn which finding it was. Each one is now
listed with its line, rule and the opening instruction of the rule's own fix
guidance; under `--apply` the line is the written file's, so it matches the
`check` that follows.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from compose_lint.cli import _line_after_edits
from compose_lint.models import TextEdit
from tests._cli_env import cli_env

REPO_ROOT = Path(__file__).resolve().parent.parent
FIX_FIXTURE = REPO_ROOT / "scripts" / "demo" / "fix-compose.yml"


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


def _stack(tmp_path: Path) -> Path:
    target = tmp_path / "docker-compose.yml"
    target.write_text(FIX_FIXTURE.read_text(encoding="utf-8"), encoding="utf-8")
    return target


def test_the_dry_run_lists_the_finding_with_its_fix(tmp_path: Path) -> None:
    _stack(tmp_path)
    proc = _run("fix", "docker-compose.yml", cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "docker-compose.yml: 1 to fix by hand:" in proc.stderr
    assert (
        "  line 3  CL-0019  Add a digest pin: "
        "image: ghcr.io/acme/api:2.4.0@sha256:<digest>"
    ) in proc.stderr
    assert "manual review" not in proc.stderr


def test_apply_reports_the_line_in_the_written_file(tmp_path: Path) -> None:
    target = _stack(tmp_path)
    proc = _run("fix", "--apply", "docker-compose.yml", cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "applied 3 fix(es)\n" in proc.stderr
    assert "  line 4  CL-0019  " in proc.stderr
    written = target.read_text(encoding="utf-8").splitlines()
    assert written[3].strip().startswith("image: ghcr.io/acme/api:2.4.0")


def test_a_lead_in_to_an_example_is_kept_as_the_instruction(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  app:\n    image: myapp:1.0\n    cap_add: [NET_ADMIN]\n",
        encoding="utf-8",
    )
    proc = _run("fix", "docker-compose.yml", cwd=tmp_path)
    assert (
        "  line 2  CL-0006  Drop all capabilities and add back only what is needed\n"
    ) in proc.stderr
    assert "  line 4  CL-0011  Remove NET_ADMIN from cap_add\n" in proc.stderr


def test_an_abbreviation_does_not_end_the_instruction() -> None:
    from compose_lint.cli import _first_sentence

    assert _first_sentence("Use a proxy, e.g. tecnativa. Then more.") == (
        "Use a proxy, e.g. tecnativa."
    )
    assert _first_sentence("No full stop here") == "No full stop here"


def test_a_finding_without_fix_text_is_summarised_from_its_message() -> None:
    from compose_lint.cli import _fix_summary
    from compose_lint.models import Finding, Severity

    finding = Finding("CL-0000", Severity.LOW, "svc", "Something is off. Details.")
    assert _fix_summary(finding) == "Something is off"


def test_an_inserted_line_above_shifts_the_line_below() -> None:
    insert = TextEdit(2, 1, 2, 1, "    read_only: true\n")
    assert _line_after_edits(3, [insert]) == 4
    assert _line_after_edits(2, [insert]) == 3
    assert _line_after_edits(1, [insert]) == 1


def test_an_edit_within_a_line_does_not_shift_it() -> None:
    rebind = TextEdit(10, 9, 10, 20, '"127.0.0.1:8080:8080"')
    assert _line_after_edits(10, [rebind]) == 10
    assert _line_after_edits(12, [rebind]) == 12


def test_a_removed_line_pulls_the_lines_below_up() -> None:
    delete = TextEdit(5, 1, 6, 1, "")
    assert _line_after_edits(8, [delete]) == 7


def test_status_lines_are_colored_when_stderr_is_a_terminal(tmp_path: Path) -> None:
    """FORCE_COLOR stands in for a terminal: stderr is a pipe under test."""
    _stack(tmp_path)
    proc = subprocess.run(
        [sys.executable, "-m", "compose_lint", "fix", "--apply", "docker-compose.yml"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=cli_env(PYTHONPATH=str(REPO_ROOT / "src"), FORCE_COLOR="1"),
        timeout=120,
    )
    err = proc.stderr
    assert "\033[33m⚠ behavior-changing · CL-0007:" in err
    assert "docker-compose.yml: \033[32mapplied 3 fix(es)\033[0m" in err
    assert "docker-compose.yml: \033[1m1 to fix by hand:\033[0m" in err
    assert "  line 4  \033[2mCL-0019\033[0m  Add a digest pin" in err


def test_status_lines_are_plain_without_color(tmp_path: Path) -> None:
    _stack(tmp_path)
    proc = _run("fix", "--apply", "docker-compose.yml", cwd=tmp_path)
    assert "\033" not in proc.stderr
