"""Tests for the rule-premise validator's Docker-unavailable handling (#378).

Runs the actual script (scripts/validate_rule_premises.py) as a subprocess with
a PATH that hides `docker`, forcing the skip path deterministically regardless
of whether the runner has Docker.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path as _Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "validate_rule_premises.py"


def _run_without_docker(
    tmp_path: _Path, **extra_env: str
) -> subprocess.CompletedProcess[str]:
    empty_bin = tmp_path / "emptybin"
    empty_bin.mkdir()
    # Override PATH so `docker` is not found (FileNotFoundError -> skip path);
    # keep the rest of the environment so the interpreter still starts.
    env = {**os.environ, "PATH": str(empty_bin)}
    env.pop("CL_REQUIRE_DOCKER", None)
    env.update(extra_env)
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        env=env,
    )


def test_skip_is_loud_when_docker_unavailable(tmp_path: _Path) -> None:
    result = _run_without_docker(tmp_path)
    # Default: a Docker-less contributor is not blocked, but the skip is loud.
    assert result.returncode == 0, result.stderr
    assert "SKIPPED" in result.stderr
    assert "Docker is not available" in result.stderr
    # A prominent banner, not a one-liner buried in output.
    assert result.stderr.count("!") > 20


def test_require_docker_makes_skip_a_hard_failure(tmp_path: _Path) -> None:
    result = _run_without_docker(tmp_path, CL_REQUIRE_DOCKER="1")
    assert result.returncode == 1, result.stderr
    assert "SKIPPED" in result.stderr
