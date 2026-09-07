"""Docker Compose as the oracle: run it, and record which one answered.

The binary is asked for the resolved configuration of a whole project
directory, with a scrubbed environment. Scrubbing is not tidiness — it is the
comparison's precondition. Compose falls back to the shell environment for an
interpolation the project does not define; compose-lint deliberately does not
([ADR-026](../../docs/adr/026-read-the-sibling-env-file.md)). Left unscrubbed,
a `PATH`-adjacent variable that happened to match a generated name would show
up as a loader disagreement that only exists inside this process.

``PATH`` alone is enough: verified against Compose 5.5.0, which resolves a
project with nothing else set.
"""

from __future__ import annotations

import functools
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

# Long enough that a slow runner is not mistaken for a hang, short enough that
# a genuine hang fails the job rather than burning its whole budget.
ORACLE_TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class OracleResult:
    """What Compose said about one project directory."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def accepted(self) -> bool:
        return self.returncode == 0


@functools.lru_cache(maxsize=1)
def oracle_version() -> str | None:
    """The Compose version answering this session, or None if none does.

    Asks the *plugin*, not the ``docker`` binary. A machine can have `docker`
    on PATH and no compose plugin behind it — the GitHub Windows runner is
    exactly that — and a `shutil.which("docker")` guard admits it, then fails
    every case with `unknown flag: --profile` from `docker` itself.

    Cached because it is a property of the machine, not of a test, and because
    a subprocess per parametrised case would cost more than the oracle calls.
    """
    if shutil.which("docker") is None:
        return None
    try:
        result = subprocess.run(
            ["docker", "compose", "version", "--short"],
            capture_output=True,
            text=True,
            timeout=ORACLE_TIMEOUT_SECONDS,
            check=False,
            env=_scrubbed_env(),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def oracle_available() -> bool:
    """Whether there is a Compose plugin to ask."""
    return oracle_version() is not None


def _scrubbed_env() -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", "")}


def run_oracle(project: Path, *, all_profiles: bool = True) -> OracleResult:
    """Resolve ``project`` the way Compose would, from inside its directory.

    ``--profile '*'`` enables every profile the project declares. compose-lint
    grades a profiled service whether or not its profile is on
    ([ADR-026](../../docs/adr/026-read-the-sibling-env-file.md), #659), and a
    default Compose run drops it — so without the flag every generated project
    with a profile would report a disagreement that is settled policy. Pass
    ``all_profiles=False`` to ask what a default run resolves, which is what
    pins that policy as a *deliberate* difference rather than an accident.
    """
    argv = ["docker", "compose"]
    if all_profiles:
        argv += ["--profile", "*"]
    argv += ["config"]
    result = subprocess.run(
        argv,
        cwd=project,
        capture_output=True,
        text=True,
        timeout=ORACLE_TIMEOUT_SECONDS,
        check=False,
        env=_scrubbed_env(),
    )
    return OracleResult(
        returncode=result.returncode, stdout=result.stdout, stderr=result.stderr
    )
