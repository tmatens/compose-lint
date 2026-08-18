"""Guard the guard for the ``fix`` round-trip smoke (#611).

The smoke's job is to fail when ``fix`` corrupts a file. A smoke that
cannot fail is worse than none — it reports coverage it does not have —
so the two detectors that carry the weight here are exercised against
inputs that must trip them.

The line-ending detector gets the closest attention: mixed endings are
the shape 0.20.0 actually shipped, and the parsed tree of such a file is
perfectly correct, so nothing above the byte level notices.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "smoke_fix_roundtrip.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("smoke_fix_roundtrip", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def smoke() -> ModuleType:
    module = _load()
    module.failures.clear()
    return module


def test_mixed_endings_are_caught(smoke: ModuleType) -> None:
    """The 0.20.0 bug: bare-LF lines spliced into a CRLF file."""
    mixed = b"services:\r\n  app:\r\n    read_only: true\n"
    smoke.check_endings("CRLF", mixed, want_crlf=True)
    assert smoke.failures, "mixed endings must be reported"
    assert "mixed line endings" in smoke.failures[0]


def test_uniform_crlf_passes(smoke: ModuleType) -> None:
    smoke.check_endings("CRLF", b"services:\r\n  app:\r\n", want_crlf=True)
    assert not smoke.failures


def test_uniform_lf_passes(smoke: ModuleType) -> None:
    smoke.check_endings("LF", b"services:\n  app:\n", want_crlf=False)
    assert not smoke.failures


def test_crlf_leaking_into_an_lf_file_is_caught(smoke: ModuleType) -> None:
    """The mirror-image splice, which is just as wrong."""
    smoke.check_endings("LF", b"services:\n  app:\r\n", want_crlf=False)
    assert smoke.failures
    assert "CRLF ending(s) introduced" in smoke.failures[0]


def test_a_lone_cr_is_caught(smoke: ModuleType) -> None:
    """A CR that is not part of a line ending is the smuggling shape."""
    smoke.check_endings("LF", b"services:\r  app:\n", want_crlf=False)
    assert smoke.failures
    assert "lone CR" in smoke.failures[0]


def test_the_loop_is_immune_to_how_git_checked_the_fixture_out(
    smoke: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The repo has no .gitattributes, so the fixture's endings vary by host.

    Git for Windows' default ``core.autocrlf=true`` hands the checkout a
    CRLF copy of a file that is LF in the repo. Read verbatim, the "LF"
    variant would then be CRLF and the "CRLF" variant ``\r\r\n`` — so the
    smoke would be asserting on the runner's git config rather than on
    ``fix``, in opposite directions per platform. That is not theoretical:
    it failed the windows-2025 leg on this branch's first run.
    """
    crlf_checkout = tmp_path / "insecure.yml"
    crlf_checkout.write_bytes(
        smoke.FIXTURE.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    )
    monkeypatch.setattr(smoke, "FIXTURE", crlf_checkout)

    smoke.smoke("LF", want_crlf=False, require_docker=False)
    smoke.smoke("CRLF", want_crlf=True, require_docker=False)
    assert not smoke.failures, smoke.failures


def test_missing_docker_fails_closed_by_default(tmp_path: Path) -> None:
    """The only external validator must not drop silently.

    A smoke that skips ``docker compose config`` and still reports green
    claims coverage it does not have, so absent Docker is an error unless
    the caller opts out. CI never opts out.
    """
    empty_bin = tmp_path / "emptybin"
    empty_bin.mkdir()
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": str(empty_bin)},
        timeout=300,
    )
    assert proc.returncode != 0
    assert "docker is not available" in proc.stdout


def test_missing_docker_can_be_downgraded_for_local_runs(tmp_path: Path) -> None:
    """...and the rest of the loop still runs, so local dev is not blocked."""
    empty_bin = tmp_path / "emptybin"
    empty_bin.mkdir()
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--allow-missing-docker"],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": str(empty_bin)},
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "SKIPPED `docker compose config`" in proc.stdout
    # Both conventions were actually exercised, not just declared.
    assert "fix round trip: LF" in proc.stdout
    assert "fix round trip: CRLF" in proc.stdout
