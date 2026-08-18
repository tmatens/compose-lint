"""A portable environment for the tests that spawn the CLI.

Several suites run ``python -m compose_lint`` as a subprocess with an
environment built from scratch rather than inherited, so a stray
``NO_COLOR``/``PYTHONPATH`` on a developer's machine cannot change what
the test observes. The dict those suites used was POSIX-shaped —
``PATH="/usr/bin:/bin"`` and nothing else — which is inert on Windows
right up until it isn't:

    Fatal Python error: _Py_HashRandomization_Init: failed to get random
    numbers to initialize Python
    Python runtime state: preinitialized

CPython 3.10 seeds hash randomization on Windows through
``CryptAcquireContext``, which locates the crypto provider relative to
``%SystemRoot%``. Drop that variable and the interpreter dies before it
runs a line of our code — every such test failing with exit 1 and no
output. 3.11+ moved to ``BCryptGenRandom``, which does not consult the
environment, which is why this only ever broke a Windows leg pinned to
the 3.10 floor (#613).

Keep the environment minimal; keep the handful of variables Windows
treats as part of the platform rather than as configuration.
"""

from __future__ import annotations

import os
import sys

# Not a wishlist: SystemRoot is the one that breaks interpreter startup,
# and the rest are what Windows expects any child process to be handed.
# Spelled uppercase because Windows resolves environment names
# case-insensitively (and os.environ upper-cases its keys there anyway), so
# SYSTEMROOT and SystemRoot are the same variable to the child process.
_WINDOWS_PLATFORM_VARS = (
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
)


def cli_env(**overrides: str) -> dict[str, str]:
    """Minimal, isolated environment for a compose-lint subprocess."""
    env = {"PATH": "/usr/bin:/bin"}
    if sys.platform == "win32":
        env["PATH"] = os.environ.get("PATH", "")
        env.update(
            {
                name: os.environ[name]
                for name in _WINDOWS_PLATFORM_VARS
                if name in os.environ
            }
        )
    env.update(overrides)
    return env
