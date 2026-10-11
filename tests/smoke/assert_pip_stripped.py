"""Prove the runtime image carries pip's metadata but none of its code.

The OpenVEX document declares every pip CVE ``not_affected`` with the
justification ``vulnerable_code_not_present``: the Dockerfile upgrades pip,
installs the wheel, then deletes pip's package directory and console scripts
while deliberately keeping its ``.dist-info`` so scanners can still identify
the version (see the comment above the runtime stage in ``Dockerfile``). Both
halves of that claim are asserted here. If pip's code came back, every VEX
statement would be false while every scanner kept honouring it; if the
metadata went missing, scanners would stop reporting pip at all, which is
evasion rather than remediation.

Runs inside the image, where there is no shell::

    docker run --rm --entrypoint /venv/bin/python3 \\
        -v "$PWD/tests/smoke/assert_pip_stripped.py:/src/check.py:ro" \\
        composelint/compose-lint:<tag> /src/check.py

Exits 0 when the image matches the VEX justification and 1 otherwise, with
one ``::error::`` line per violation. Shared by the PR Dockerfile smoke
(``ci.yml``) and the release smoke (``release-docker-smoke.yml``).
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import sys
import sysconfig
from pathlib import Path


def main() -> int:
    problems: list[str] = []

    if importlib.util.find_spec("pip") is not None:
        problems.append("`import pip` resolves: pip's package code is present")

    purelib = Path(sysconfig.get_paths()["purelib"])
    if (purelib / "pip").exists():
        problems.append(f"{purelib / 'pip'} exists: pip's package code is present")

    # sysconfig's scripts path is the venv's own bin directory. Deriving it
    # from sys.executable and resolving the symlink would land in the base
    # interpreter's bin instead (/usr/bin in the image), the wrong place.
    bindir = Path(sysconfig.get_paths()["scripts"])
    minor = f"pip{sys.version_info.major}.{sys.version_info.minor}"
    for name in ("pip", "pip3", minor):
        if (bindir / name).exists():
            problems.append(f"{bindir / name} exists: pip's console script is present")

    try:
        version = importlib.metadata.version("pip")
    except importlib.metadata.PackageNotFoundError:
        problems.append(
            "pip's .dist-info is missing: scanners can no longer identify pip, "
            "which hides CVEs instead of removing their code"
        )
    else:
        print(f"pip {version}: metadata present, scanners can identify it")

    if problems:
        for problem in problems:
            print(f"::error::{problem}")
        return 1

    print("pip code absent: the OpenVEX vulnerable_code_not_present statements hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
