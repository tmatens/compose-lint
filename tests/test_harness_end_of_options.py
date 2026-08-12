"""Every shipped harness must terminate the option namespace with ``--``.

A repository can contain a *directory* named ``--config=cfgdir`` holding a
``compose.yml``. The resulting path ``--config=cfgdir/compose.yml`` matches the
pre-commit hook's ``files:`` regex and the Action's discovery, so a harness that
globs repo paths straight into argv hands argparse something it reads as an
option: the crafted file leaves the lint set *and* an attacker-authored policy
disabling every rule is installed for the run. The gate goes green over a
privileged, ``docker.sock``-mounting stack.

The defense has to live in the callers. The CLI cannot distinguish a genuine
``--config=x`` from a file that happens to be named that, and inserting ``--``
inside the argv shim would break the documented
``compose-lint init docker-compose.yml -o ci.yml`` form, where flags follow a
positional. These tests therefore pin the harnesses, and one end-to-end case
proves the separator is what changes the verdict.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

_COMPOSE = (
    "services:\n"
    "  web:\n"
    "    image: nginx:latest\n"
    "    privileged: true\n"
    "    volumes:\n"
    "      - /var/run/docker.sock:/var/run/docker.sock\n"
    "    cap_add:\n"
    "      - SYS_ADMIN\n"
)
_ATTACKER_POLICY = (
    'rules:\n  CL-0001: {enabled: false, reason: "x"}\n'
    '  CL-0002: {enabled: false, reason: "x"}\n'
    '  CL-0024: {enabled: false, reason: "x"}\n'
)


def _hook() -> dict[str, Any]:
    hooks = yaml.safe_load((REPO_ROOT / ".pre-commit-hooks.yaml").read_text())
    return next(h for h in hooks if h["id"] == "compose-lint")


def test_precommit_default_args_terminate_options() -> None:
    """pre-commit runs ``entry + args + filenames``, so ``--`` must end ``args``.

    Not the end of ``entry``: a user's own ``args:`` would then land *after* the
    separator and be read as paths. Verified against pre-commit 4.x —
    ``compose-lint -- --fail-on low docker-compose.yml`` reports two files that
    could not be parsed and exits 2.
    """
    hook = _hook()
    assert hook["entry"].split() == ["compose-lint"], hook["entry"]
    assert hook.get("args", [])[-1:] == ["--"], (
        f"default args must end with `--`, got {hook.get('args')!r}"
    )


def test_precommit_entry_does_not_carry_the_separator() -> None:
    """Pins the reason for the placement, so it is not 'tidied' back later."""
    assert "--" not in _hook()["entry"].split()


def test_action_passes_double_dash_before_the_file_list() -> None:
    """Both invocations — the text run and the SARIF re-run — need it."""
    action = (REPO_ROOT / "action.yml").read_text(encoding="utf-8")
    invocations = [
        line.strip()
        for line in action.splitlines()
        if "compose-lint" in line and "$CL_TARGET_FILES" in line
    ]
    assert len(invocations) == 2, f"expected 2 invocations, found {invocations!r}"
    for line in invocations:
        assert "-- $CL_TARGET_FILES" in line, f"missing `--` separator: {line!r}"


def test_double_dash_is_what_changes_the_verdict(tmp_path: Path) -> None:
    """End-to-end: same argv, separator alone flips the false pass to a fail."""
    (tmp_path / "compose.yml").write_text(_COMPOSE, encoding="utf-8")
    (tmp_path / "cfgdir").mkdir()
    (tmp_path / "cfgdir" / "compose.yml").write_text(_ATTACKER_POLICY, encoding="utf-8")
    # To git this is a directory named `--config=cfgdir` holding a compose file.
    (tmp_path / "--config=cfgdir").mkdir()
    (tmp_path / "--config=cfgdir" / "compose.yml").write_text(
        _ATTACKER_POLICY, encoding="utf-8"
    )

    argv = ["--config=cfgdir/compose.yml", "cfgdir/compose.yml", "compose.yml"]

    def run(args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "compose_lint", *args],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            env={"PYTHONPATH": str(REPO_ROOT / "src"), "PATH": "/usr/bin:/bin"},
            timeout=120,
        )

    without = run(argv)
    with_separator = run(["--", *argv])

    assert without.returncode == 0, "precondition: the unseparated form passes"
    assert with_separator.returncode == 1, (
        "with `--` the crafted path must be linted as a file, not read as a "
        f"config flag; got exit {with_separator.returncode}"
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["init", "docker-compose.yml", "-o", "out.yml"],
        ["init", "docker-compose.yml", "--force"],
    ],
)
def test_flags_after_a_positional_still_work(tmp_path: Path, argv: list[str]) -> None:
    """Why the shim cannot insert ``--`` itself: this form is documented.

    ``compose-lint init docker-compose.yml -o ci.yml`` appears in README.md and
    docs/configuration.md. An end-of-options marker before the first positional
    would turn ``-o`` into a path and break it, which is why the separator is
    the caller's job.
    """
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx:1.27\n", encoding="utf-8"
    )
    proc = subprocess.run(
        [sys.executable, "-m", "compose_lint", *argv],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={"PYTHONPATH": str(REPO_ROOT / "src"), "PATH": "/usr/bin:/bin"},
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
