"""Differential test: does our file selection agree with Docker Compose?

``COMPOSE_FILE`` semantics were derived by probing ``docker compose config``,
and the load-bearing one is easy to state and easy to forget: setting it
**suppresses** the automatic ``compose.override.yml`` merge, because it replaces
discovery and the override is something discovery finds. ADR-025 shipped that
merge as unconditional, so compose-lint reported a CRITICAL from a document
Compose never loads.

Comments rot, so this re-derives it from the binary on every run: which
documents Compose actually merged is read back out of ``config``, and compared
against the group ``_selection`` planned.

Skipped when the ``docker compose`` CLI is unavailable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest
import yaml

from compose_lint._selection import plan_documents

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


def _compose_cli_works() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return (
            subprocess.run(
                ["docker", "compose", "version"], capture_output=True, timeout=30
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


pytestmark = pytest.mark.skipif(
    not _compose_cli_works(),
    reason="differential selection test needs a working docker compose CLI",
)

# The one place agreement with the *lint host's* Compose is not the goal.
#
# Compose defaults COMPOSE_PATH_SEPARATOR to the host's path separator, so a
# `.env` reading `COMPOSE_FILE=a.yml:b.yml` names two documents on Linux and one
# oddly-named document on Windows. compose-lint splits on ":" everywhere: the
# separator is a property of the project, and a Compose file linted on a Windows
# laptop is overwhelmingly headed for a Linux host. ADR-023 clause 1 settled the
# same question for path semantics ("POSIX notation on every platform") after
# issue #588, where matching the host silently broke the highest-severity rules.
#
# So cases that are *not* about the default separator set one explicitly, which
# behaves identically on both platforms and lets the merge and suppression
# assertions run everywhere. The default itself gets its own case below.
POSIX_DEFAULT_SEPARATOR = os.pathsep == ":"
SEP = "COMPOSE_PATH_SEPARATOR=,\n"

# Each document sets a distinct marker, so which ones Compose merged can be read
# straight out of the effective configuration.
# Every document carries `image:` so that *any* subset of them is a valid
# project on its own. Without that, a case selecting one document alone was
# rejected by Compose and silently skipped rather than compared.
DOCUMENTS = {
    "compose.yml": (
        "services:\n  web:\n    image: i\n    environment:\n      BASE: '1'\n"
    ),
    "compose.override.yml": (
        "services:\n  web:\n    image: i\n    environment:\n      OVERRIDE: '1'\n"
    ),
    "compose.prod.yml": (
        "services:\n  web:\n    image: i\n    environment:\n      PROD: '1'\n"
    ),
}


@pytest.fixture
def project(tmp_path: Path) -> Iterator[Path]:
    for name, text in DOCUMENTS.items():
        (tmp_path / name).write_text(text, encoding="utf-8", newline="")
    previous = os.getcwd()
    os.chdir(tmp_path)
    try:
        yield tmp_path
    finally:
        os.chdir(previous)


def _compose_merged(directory: Path) -> set[str]:
    """Which documents Compose actually loaded, named by their marker."""
    result = subprocess.run(
        ["docker", "compose", "config"],
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"compose rejected the fixture, so nothing was compared: "
        f"{result.stderr.strip()[:200]}"
    )
    env = yaml.safe_load(result.stdout)["services"]["web"].get("environment") or {}
    markers = {
        "BASE": "compose.yml",
        "OVERRIDE": "compose.override.yml",
        "PROD": "compose.prod.yml",
    }
    return {name for key, name in markers.items() if key in env}


def write_env(directory: Path, text: str) -> None:
    (directory / ".env").write_text(text, encoding="utf-8", newline="")


def _planned(directory: Path) -> set[str]:
    from pathlib import PurePath

    return {
        PurePath(path).name
        for group in plan_documents([]).groups
        for path in group.paths
    }


def test_discovery_matches(project: Path) -> None:
    """No .env: base plus the sibling override, which is ADR-025's behaviour."""
    assert (
        _planned(project)
        == _compose_merged(project)
        == {
            "compose.yml",
            "compose.override.yml",
        }
    )


def test_compose_file_matches(project: Path) -> None:
    write_env(project, SEP + "COMPOSE_FILE=compose.yml,compose.prod.yml\n")
    assert _planned(project) == _compose_merged(project)


def test_compose_file_suppresses_the_override(project: Path) -> None:
    """The whole reason this ADR touched already-shipped behaviour."""
    write_env(project, SEP + "COMPOSE_FILE=compose.yml,compose.prod.yml\n")
    merged = _compose_merged(project)
    assert "compose.override.yml" not in merged
    assert _planned(project) == merged


def test_single_entry_matches(project: Path) -> None:
    write_env(project, "COMPOSE_FILE=compose.prod.yml\n")
    assert _planned(project) == _compose_merged(project) == {"compose.prod.yml"}


def test_custom_separator_matches(project: Path) -> None:
    write_env(project, SEP + "COMPOSE_FILE=compose.yml,compose.prod.yml\n")
    assert _planned(project) == _compose_merged(project)


@pytest.mark.skipif(
    POSIX_DEFAULT_SEPARATOR,
    reason="the divergence only exists where the host separator is not ':'",
)
def test_the_default_separator_deliberately_differs_on_windows(project: Path) -> None:
    """We split on ":" here and Compose-on-Windows does not. That is the point.

    A `.env` written ``COMPOSE_FILE=a.yml:b.yml`` describes a project that
    deploys on Linux. Reading it the Windows way would grade a different set of
    documents than the one that runs -- a finding true only of the lint host,
    which is what ADR-023 exists to prevent. Asserted rather than skipped so the
    divergence stays visible and intentional.
    """
    write_env(project, "COMPOSE_FILE=compose.yml:compose.prod.yml\n")
    assert _planned(project) == {"compose.yml", "compose.prod.yml"}

    result = subprocess.run(
        ["docker", "compose", "config"],
        cwd=project,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode != 0, (
        "Compose on this host now reads ':' as a separator too, so the "
        "divergence is gone and this case belongs with the agreeing ones"
    )
