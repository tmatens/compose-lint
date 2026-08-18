"""The CLI-subprocess environment must stay isolated *and* startable.

Two properties in tension. Isolation is why the environment is built from
scratch instead of inherited. Startability is what that cost on Windows:
without ``SystemRoot`` CPython 3.10 cannot seed hash randomization and
dies at preinitialization, so every test using it failed with exit 1 and
no output at all (#613's 3.10 Windows leg found this).

A regression in either direction is silent — one lets the developer's
shell leak into assertions, the other only shows up on one OS at one
Python version — so both get pinned here.
"""

from __future__ import annotations

import os
import sys

from tests._cli_env import cli_env


def test_the_environment_stays_minimal() -> None:
    """Isolation is the reason this env is constructed rather than inherited."""
    env = cli_env(PYTHONPATH="/x", NO_COLOR="1")
    assert env["PYTHONPATH"] == "/x"
    assert env["NO_COLOR"] == "1"
    # Nothing that would let an ambient setting change what a test observes.
    for leaked in ("COMPOSE_LINT_CONFIG", "PYTHONWARNINGS", "PYTHONSTARTUP"):
        assert leaked not in env


def test_overrides_win() -> None:
    assert cli_env(PATH="/only/here")["PATH"] == "/only/here"


def test_windows_keeps_what_the_interpreter_needs_to_start() -> None:
    """``SYSTEMROOT`` is not configuration; it is how Windows finds the CSP."""
    env = cli_env(PYTHONPATH="/x")
    if sys.platform != "win32":
        # The POSIX baseline stays deliberately bare.
        assert env["PATH"] == "/usr/bin:/bin"
        return
    assert "SYSTEMROOT" in env, (
        "dropping SystemRoot makes CPython 3.10 fail at preinitialization with "
        "_Py_HashRandomization_Init, before any compose-lint code runs"
    )
    assert env["SYSTEMROOT"] == os.environ["SYSTEMROOT"]
