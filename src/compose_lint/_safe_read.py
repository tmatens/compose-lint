"""Bounded reads of files compose-lint was pointed at.

``Path.exists()`` and ``open()`` answer "is there something here", not "is this
a file I can safely read to the end". Both are true of a FIFO and of
``/dev/zero``, and a repository can commit a *symlink* to either — the link is
an ordinary tracked object, so it survives clone and checkout and the runner
resolves it. Reading one hangs the job forever; reading the other allocates
until the runner is killed. Neither produces a finding, an error, or a verdict.

So the shape of the target is checked before any bytes are read (``S_ISREG``,
on the resolved file, not the link), and the read is bounded rather than
unbounded. A Compose file or a policy file is a human-authored document of a
few kilobytes; the caps here are far above anything real and exist only to make
the failure a message instead of an outage.
"""

from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

# Generous by design. The largest file in a 5,417-file corpus of real-world
# Compose documents is well under 200 KB, so this bounds the pathological case
# without being a limit anyone writing a Compose file can reach.
MAX_FILE_BYTES = 8 * 1024 * 1024


class UnsafeFileError(OSError):
    """Raised when a path is not a regular file, or is larger than the cap."""


class OutsideProjectError(UnsafeFileError):
    """Raised when a path resolves outside the project it was named from."""


def escapes_project(path: Path, project: Path) -> bool:
    """Whether ``path`` resolves outside ``project`` on *this* filesystem.

    The lexical guards in :mod:`compose_lint._selection` and
    :mod:`compose_lint._service_env` answer a different question, and
    deliberately so: whether a path *says* it leaves the project is a fact
    about the document, identical on every platform (ADR-023 §1). A symlink is
    not visible in what the path says. ``probe.env`` is spelled like a
    project-relative file and passes every lexical test, while the committed
    link beside it points at ``/home/runner/.aws/credentials`` — the scenario
    ADR-027 §7 names and promises to refuse.

    So this is a *second* gate rather than a replacement: asked at the moment
    of reading, about this filesystem, after the lexical test has already
    ruled on the document. Both have to pass.
    """
    try:
        resolved = path.resolve()
        root = project.resolve()
    except OSError:  # pragma: no cover - resolution failed; treat as escaping
        return True
    return not resolved.is_relative_to(root)


def read_text_bounded(
    path: Path,
    *,
    max_bytes: int = MAX_FILE_BYTES,
    newline: str | None = None,
    within: Path | None = None,
) -> str:
    """Read ``path`` as UTF-8, refusing anything that is not a bounded regular file.

    ``newline=""`` disables universal-newline translation for callers that need
    the file's real bytes.

    Raises :class:`UnsafeFileError` for a FIFO, device, socket or directory, and
    for a regular file over ``max_bytes``. ``FileNotFoundError`` still surfaces
    for a missing path, because "not there" and "not readable safely" are
    different answers and callers already distinguish them.

    The descriptor is opened first and inspected with ``fstat``, so the check
    and the read see the same object — a path re-pointed between the two cannot
    slip a FIFO past a ``stat`` that saw a regular file.

    ``O_NONBLOCK`` is what makes that ordering possible: opening a FIFO for
    reading blocks until a writer appears, so a plain ``open()`` hangs *before*
    any check can run. It has no effect on a regular file. Symlinks are
    deliberately followed — a symlink to a real Compose file is ordinary, and
    it is the resolved target's shape that matters.

    Both extra flags are POSIX-vs-Windows conditional, hence the ``getattr``:
    Windows has no ``O_NONBLOCK`` — and no FIFO whose open would block this
    way, so nothing is lost — and referencing it unconditionally crashed every
    file read on Windows in 0.18.0. ``O_BINARY`` exists only on Windows, where
    omitting it makes the CRT translate newlines *under* the text layer below,
    silently breaking the ``newline=""`` real-bytes contract.

    ``within`` adds the physical containment gate: the path must *resolve*
    inside that directory. Symlinks are still followed for the shape check —
    a symlink to a real Compose file is ordinary — but a link whose target
    leaves the project is refused with :class:`OutsideProjectError` when the
    caller names a project. Callers that were pointed at a file by the user
    (an argv path, ``--config``) pass nothing and are unaffected; callers
    opening a path *the document named* pass the project directory.
    """
    if within is not None and escapes_project(path, within):
        raise OutsideProjectError(
            f"{path} resolves outside the project directory (refused rather than read)"
        )
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise UnsafeFileError(
                f"{path} is not a regular file (reading it could block "
                "forever or never end)"
            )
        if info.st_size > max_bytes:
            raise UnsafeFileError(
                f"{path} is {info.st_size} bytes, over the {max_bytes}-byte limit"
            )
        with os.fdopen(fd, "r", encoding="utf-8", newline=newline) as handle:
            fd = -1  # ownership passed to the context manager
            # Bounded even though the size was checked: a regular file can grow
            # between fstat and read, and the point of this module is that no
            # read here is unbounded.
            content = handle.read(max_bytes + 1)
    finally:
        if fd >= 0:
            os.close(fd)

    if len(content) > max_bytes:
        raise UnsafeFileError(f"{path} exceeds the {max_bytes}-byte limit")
    return content
