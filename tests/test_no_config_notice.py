"""Saying when no config is in effect — and staying quiet otherwise (#625).

``.compose-lint.yml`` is discovered in the current working directory. Inside
the image that is ``/src``, so a ``docker run`` that mounts only the compose
file leaves the config outside the container and every suppression the user
wrote silently absent. It fails toward *more* findings, which reads as the
tool being noisy rather than as a mount mistake.

It cannot be an error: a config that was never mounted is indistinguishable
from one that was never written, and most runs legitimately have no config.
So the contract is narrow, and both halves of it are load-bearing — a notice
that fires on every green run stops being read, and one that never fires
explains nothing.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests._cli_env import cli_env

REPO_ROOT = Path(__file__).resolve().parent.parent
NOTICE = "no .compose-lint.yml found"

_INSECURE = "services:\n  app:\n    image: myapp:1.0\n    privileged: true\n"
_CLEAN = (
    "services:\n  web:\n    image: nginx:1.27-alpine@sha256:"
    + "0" * 64
    + '\n    ports:\n      - "127.0.0.1:8080:80"\n'
    "    security_opt:\n      - no-new-privileges:true\n"
    "    cap_drop:\n      - ALL\n    read_only: true\n"
    "    mem_limit: 512m\n    cpus: 0.5\n    tmpfs:\n      - /tmp\n"
)


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
def stack(tmp_path: Path) -> Path:
    (tmp_path / "docker-compose.yml").write_text(_INSECURE, encoding="utf-8")
    return tmp_path


def test_a_failing_check_says_no_config_was_in_effect(stack: Path) -> None:
    """The moment the user asks "why is this failing?"."""
    proc = _run("check", "docker-compose.yml", cwd=stack)
    assert proc.returncode == 1
    assert NOTICE in proc.stderr
    # Naming the directory is the whole diagnosis for the Docker case — a
    # user seeing /src knows immediately what they failed to mount.
    assert str(stack) in proc.stderr


def test_the_notice_is_on_stderr_only(stack: Path) -> None:
    """It must never reach a machine consumer's data stream."""
    for fmt in ("json", "sarif"):
        proc = _run("check", "--format", fmt, "docker-compose.yml", cwd=stack)
        assert NOTICE not in proc.stdout, f"{fmt} stdout carries the notice"
        assert NOTICE in proc.stderr, f"{fmt} run lost the notice entirely"


def test_a_passing_check_stays_quiet(tmp_path: Path) -> None:
    """Noise on green runs is how a diagnostic stops being read."""
    (tmp_path / "docker-compose.yml").write_text(_CLEAN, encoding="utf-8")
    proc = _run("check", "docker-compose.yml", cwd=tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert NOTICE not in proc.stderr


def test_a_config_that_was_found_stays_quiet(stack: Path) -> None:
    (stack / ".compose-lint.yml").write_text(
        'rules:\n  CL-0002:\n    enabled: false\n    reason: "test"\n',
        encoding="utf-8",
    )
    proc = _run("check", "docker-compose.yml", cwd=stack)
    assert NOTICE not in proc.stderr


def test_an_explicit_config_stays_quiet(stack: Path) -> None:
    """--config elsewhere is not a missing config."""
    cfg = stack / "policy.yml"
    cfg.write_text(
        'rules:\n  CL-0003:\n    enabled: false\n    reason: "test"\n',
        encoding="utf-8",
    )
    proc = _run("check", "--config", str(cfg), "docker-compose.yml", cwd=stack)
    assert NOTICE not in proc.stderr


def test_fix_says_it_too(stack: Path) -> None:
    """`fix` honours suppressions, so a missing config changes what is written.

    That makes this the more consequential of the two: `check` reports a
    state, `fix` mutates the user's file.
    """
    proc = _run("fix", "docker-compose.yml", cwd=stack)
    assert NOTICE in proc.stderr


def test_fix_with_nothing_to_do_stays_quiet(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(_CLEAN, encoding="utf-8")
    proc = _run("fix", "docker-compose.yml", cwd=tmp_path)
    assert NOTICE not in proc.stderr
