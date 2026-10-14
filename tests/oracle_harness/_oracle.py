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
    from collections.abc import Mapping
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


# The variables that decide which compose plugin the docker CLI runs: its
# config directory (DOCKER_CONFIG, else under HOME / USERPROFILE), the
# system plugin directories (ProgramData / ProgramFiles on Windows), and PATH
# for `docker` itself. Nothing else in an environment changes the lookup.
_LOOKUP_VARS = (
    "PATH",
    "HOME",
    "DOCKER_CONFIG",
    "USERPROFILE",
    "ProgramData",
    "ProgramFiles",
)


# `docker info` template that prints the compose plugin's path. One string
# literal, not two adjacent ones: implicit concatenation inside an argv list
# is indistinguishable from a missing comma (CodeQL
# py/implicit-string-concatenation-in-list).
_PLUGIN_PATH_FORMAT = (
    '{{range .ClientInfo.Plugins}}{{if eq .Name "compose"}}{{.Path}}{{end}}{{end}}'
)


def compose_argv(env: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """The command that runs Compose for a call made with ``env``.

    ``docker compose …`` starts the ``docker`` CLI, which discovers and
    execs the plugin; the plugin binary run on its own answers the same
    question without that front-end. The differential suites call Compose
    about three thousand times a run, and the front-end was roughly 45% of
    each call (76 ms against 42 ms on Compose 5.5.0, same output), which
    made it the largest single cost in the test suite.

    ``env`` is the environment the call will run with (``None``: this
    process's). The binary is resolved under that same environment, because
    the environment decides which plugin ``docker compose`` runs: a
    ``DOCKER_CONFIG`` in one and not the other is two different binaries.
    The path comes from the ``docker`` CLI itself (``docker info`` lists the
    client plugins and their paths without contacting a daemon), so it is
    the binary ``docker compose`` would have run, not one found by a search
    order of our own. It is used only if it reports the same version as
    ``docker compose`` under that environment; anything else falls back to
    the front-end, which is slower but cannot be the wrong binary.
    """
    source = os.environ if env is None else env
    return _resolve_compose(tuple((name, source.get(name)) for name in _LOOKUP_VARS))


@functools.lru_cache(maxsize=8)
def _resolve_compose(lookup: tuple[tuple[str, str | None], ...]) -> tuple[str, ...]:
    fallback = ("docker", "compose")
    env = {name: value for name, value in lookup if value is not None}
    if shutil.which("docker", path=env.get("PATH")) is None:
        return fallback
    try:
        info = subprocess.run(
            [
                "docker",
                "info",
                "--format",
                _PLUGIN_PATH_FORMAT,
            ],
            capture_output=True,
            text=True,
            timeout=ORACLE_TIMEOUT_SECONDS,
            check=False,
            env=env,
        )
        path = info.stdout.strip()
        if not path or not os.access(path, os.X_OK):
            return fallback
        versions = [
            subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=ORACLE_TIMEOUT_SECONDS,
                check=False,
                env=env,
            )
            for argv in (
                ["docker", "compose", "version", "--short"],
                [path, "version", "--short"],
            )
        ]
    except (OSError, subprocess.SubprocessError):
        return fallback
    if (
        any(v.returncode != 0 for v in versions)
        or len({v.stdout.strip() for v in versions}) != 1
    ):
        return fallback
    return (path,)


def _scrubbed_env() -> dict[str, str]:
    return {"PATH": os.environ.get("PATH", "")}


def run_oracle(
    project: Path,
    *,
    all_profiles: bool = True,
    files: tuple[str, ...] = (),
    project_name: str = "oracle",
    environment: Mapping[str, str] | None = None,
) -> OracleResult:
    """Resolve ``project`` the way Compose would, from inside its directory.

    ``--profile '*'`` enables every profile the project declares. compose-lint
    grades a profiled service whether or not its profile is on
    ([ADR-026](../../docs/adr/026-read-the-sibling-env-file.md), #659), and a
    default Compose run drops it — so without the flag every generated project
    with a profile would report a disagreement that is settled policy. Pass
    ``all_profiles=False`` to ask what a default run resolves, which is what
    pins that policy as a *deliberate* difference rather than an accident.

    ``files`` names documents explicitly instead of letting Compose discover
    them, which is how the shape comparator asks about its dump without the
    project's own documents joining in.

    ``project_name`` is fixed rather than derived from the directory, because
    Compose writes it into the output — as ``name:`` and inside the default
    network's ``<project>_default`` — and two resolutions being compared have
    to agree on it.

    ``environment`` adds names on top of ``PATH``. It exists for exactly one
    caller: the registered divergence whose *subject* is Compose's shell-
    environment fallback, which cannot be demonstrated without one. Everything
    else runs scrubbed, and should.
    """
    env = _scrubbed_env()
    if environment:
        env.update(environment)
    argv = [*compose_argv(env), "--project-name", project_name]
    if all_profiles:
        argv += ["--profile", "*"]
    for name in files:
        argv += ["-f", name]
    argv += ["config"]
    result = subprocess.run(
        argv,
        cwd=project,
        capture_output=True,
        text=True,
        timeout=ORACLE_TIMEOUT_SECONDS,
        check=False,
        env=env,
    )
    return OracleResult(
        returncode=result.returncode, stdout=result.stdout, stderr=result.stderr
    )
