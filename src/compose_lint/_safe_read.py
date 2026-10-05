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
from pathlib import Path

# How a refusal by :func:`out_of_reach` reads, wherever it is reported. It
# names the physical gate (a link), as distinct from the lexical refusal of a
# path that *says* it leaves ("resolves outside the repository").
OUT_OF_REACH = "resolves through a symlink to a target outside the repository"

# The marker that makes a directory the root of a repository: a directory in an
# ordinary checkout, a file in a worktree or a submodule.
GIT_MARKER = ".git"

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


def containment_root(project: Path) -> Path:
    """The directory a project's references may reach into (ADR-038).

    Every file a run opens because a document named it is contained to one
    root, and this is where that root comes from. In order:

    1. **The repository.** The nearest directory at or above ``project`` that
       holds a ``.git`` entry — a directory in a checkout, a file in a worktree
       or a submodule, so a submodule is its own root. In CI this is the
       checkout, and a target inside it is content the change under review can
       already see: reading it discloses nothing, and refusing it failed the
       ordinary monorepo layouts (``include: ../common/compose.yaml``, a shared
       base at the repository root) that Compose deploys. Found by walking
       parents, never by running ``git``: the result is the same whether or
       not git is installed, and nothing is executed on the lint host's behalf.
    2. **The run directory**, when there is no repository and it contains the
       project. A tarball checkout linted from its top keeps what 0.32.0's link
       rule gave it. A filesystem root is never used: a run from ``/`` would
       otherwise make every file on the machine reachable.
    3. **The project directory** itself, which is where the rule started.

    The walk is lexical over ``project.absolute()`` with its ``..`` segments
    folded, not ``resolve()``, for the reason the bind-source code gives:
    Compose takes the project directory from the path as given, links
    included. Whether the run directory contains the project is asked of the
    filesystem, as the link rule it replaces asked it.
    """
    start = Path(os.path.normpath(project.absolute()))
    for candidate in (start, *start.parents):
        if (candidate / GIT_MARKER).exists():
            return candidate
    try:
        cwd = Path.cwd()
    except OSError:  # pragma: no cover - the run directory was removed under us
        return start
    if cwd != Path(cwd.anchor) and not escapes_project(start, cwd):
        return cwd
    return start


def inside_git_dir(path: Path, root: Path) -> bool:
    """Whether ``path`` resolves into a ``.git`` directory under ``root``.

    The repository root is defined by its ``.git``, and that directory is the
    one place inside a checkout that is not the change under review: a CI
    checkout writes the job's credential into ``.git/config`` by default. So it
    is never read, however the path got there — a ``..`` spelling is refused
    lexically by :func:`~compose_lint._service_env.project_relative`, and a
    link into it here.
    """
    try:
        relative = path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):  # pragma: no cover - outside, or unresolvable
        return True
    return GIT_MARKER in relative.parts


def out_of_reach(path: Path, root: Path) -> bool:
    """Whether ``path`` resolves outside the containment root of ``root``.

    This is the one link rule for every file a run opens. ``root`` is the
    directory the site already contains the read to: the project directory
    for a ``.env``, an ``include:`` or ``extends:`` target, a ``COMPOSE_FILE``
    entry or an ``env_file:``, and the link's own directory for a Compose file
    the run picked up. It is widened here to :func:`containment_root`, so a
    link whose target stays inside the repository is followed, as Compose
    follows it, and one that leaves the repository — or lands in its ``.git``
    — is refused, which is the case containment exists for: a committed link
    pointing somewhere else on the machine.

    Each site used to pick its own root, so the same link was followed as a
    Compose file and refused as the ``.env`` beside it. Asking this one
    question everywhere keeps them from drifting apart again.
    """
    reach = containment_root(root)
    return escapes_project(path, reach) or inside_git_dir(path, reach)


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
    inside that directory's containment root (:func:`out_of_reach`). Symlinks
    are still followed for the shape check — a symlink to a real Compose file
    is ordinary — but a link whose target leaves the root is refused with
    :class:`OutsideProjectError` when the caller names a project. Callers that
    were pointed at a file by the user (an argv path, ``--config``) pass
    nothing and are unaffected; callers opening a path *the document named*
    pass the project directory.
    """
    if within is not None and out_of_reach(path, within):
        raise OutsideProjectError(f"{path} {OUT_OF_REACH} (refused rather than read)")
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
