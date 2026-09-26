"""Guard for tests that must execute a script they just wrote to a tmpdir.

Several suites write a small shell script into ``tmp_path``, mark it
executable, and then assert on whether something ran it — a ``pip`` shim
standing in for the Action's install step, a fake ``$PAGER``. All of them
are silently wrong when ``TMPDIR`` cannot execute files, which is the case
on any host that mounts ``/tmp`` ``noexec``. That is a CIS-recommended
hardening, not an exotic setting, and CI never sees it: the runners'
``/tmp`` is exec, so nothing here can go red upstream.

The failure is bad in both directions, and the quiet one is worse:

- A test asserting the script **did** run fails, and reads like a genuine
  defect in the code under test rather than a property of the machine.
- A test asserting the script **did not** run passes *vacuously*. It cannot
  run, so "it didn't" is trivially true and the assertion stops testing
  anything while still reporting green.

There was a third, since fixed (#595/#597): PATH resolution silently passes
over a non-executable entry, so a bypassed ``pip`` shim reached the real
``pip``, which replaced the editable checkout with a published
``compose-lint`` and corrupted every later run in a way that read like
source breakage.

So never let one of these fall through. Probe an exec up front and skip with
the remedy. ``scripts/preflight.sh`` sets an exec-capable ``TMPDIR`` first
(#880), so there this is a backstop; it is the normal path only for a bare
``pytest`` on a noexec host.
"""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


def require_exec(directory: Path) -> None:
    """Skip the calling test when ``directory`` cannot execute files."""
    probe = directory / "exec-probe"
    probe.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    probe.chmod(0o755)
    try:
        subprocess.run([str(probe)], check=True, timeout=10)
    except OSError:
        pytest.skip(
            f"{directory} cannot execute files (noexec tmpdir?) — run "
            "scripts/preflight.sh, which picks an exec-capable TMPDIR, or set "
            "TMPDIR yourself, see CONTRIBUTING.md"
        )
    finally:
        probe.unlink()
