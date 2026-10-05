"""Decide which documents a run grades, the way Compose decides it.

``docker compose up`` picks its documents three ways, in this order of
precedence: an explicit ``-f``, a ``COMPOSE_FILE`` in the environment, and
otherwise discovery of a canonical filename plus the ``compose.override.yml``
sitting beside it. compose-lint follows the same shape under
[ADR-026](../../docs/adr/026-read-the-sibling-env-file.md) — *use files as
Docker Compose would, when run in that file's directory* — with the ambient
shell deliberately left out, because a ``COMPOSE_FILE`` exported in someone's
session and never written down is host state by any reading.

Two consequences are easy to miss and both are load-bearing.

**``COMPOSE_FILE`` suppresses the override merge.** It replaces discovery
outright, and ``compose.override.yml`` is something discovery finds, so Compose
does not load it (verified). ADR-025 shipped that merge as unconditional, which
made compose-lint report findings from a document Compose never reads, under a
warning asserting that Compose merges it automatically.

**A named file is never dropped.** ADR-026 §4: ``.env`` may *expand* what is
graded, never shrink it for a file the user named. A runtime does what it is
told; a gate must not let the artifact under inspection define its own scope,
which is ShellCheck's reason for refusing to let a checked script enable
``external-sources`` for itself. Both first-party integrations pass explicit
file lists — pre-commit appends filenames, ``action.yml`` passes
``TARGET_FILES`` — so without this rule a contributor could shrink a CI gate by
committing one file. In bare discovery there is no named file to protect and
``COMPOSE_FILE`` replaces discovery exactly as Compose does.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from compose_lint._env_file import ENV_FILENAME, env_read_failure, read_env
from compose_lint._safe_read import out_of_reach

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = [
    "COMPOSE_FILE_KEYS",
    "DocumentGroup",
    "Selection",
    "plan_documents",
]

# The names Compose discovers when nothing selects files for it.
COMPOSE_FILENAMES = [
    "compose.yml",
    "compose.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
]

# The overlay Compose merges automatically when it sits beside a base file.
# Measured against Compose 5.5.0: the spelling of the base does not matter.
# Any of the four base names takes whichever override exists, and when several
# do, the first in this order wins (Compose warns and names it). Pairing only
# the matching spelling missed `compose.yaml` + `docker-compose.override.yml`,
# which Compose deploys.
OVERRIDE_SEARCH = (
    "compose.override.yml",
    "compose.override.yaml",
    "docker-compose.override.yml",
    "docker-compose.override.yaml",
)

# The only keys read from a `.env` for selection. Fixed and tiny on purpose:
# the wanted-set filter (ADR-026 §5) needs to know what to keep before anything
# else about the project is known, and this is that list.
COMPOSE_FILE_KEYS = ("COMPOSE_FILE", "COMPOSE_PATH_SEPARATOR")

# Compose's default separator is the host's path separator, which would make the
# same `.env` select different documents on a Windows lint host than on the
# Linux host the stack deploys to. ADR-023 §1 already settled that question for
# path semantics -- "lexical segment math in POSIX notation on every platform" --
# and the same reasoning applies: the separator is a property of the project,
# not of the machine reading it. A Windows drive letter is not a counter-example,
# because an absolute entry is refused by `_resolve_entry` either way.
DEFAULT_PATH_SEPARATOR = ":"

# The gaps for a Compose file that is a link resolving outside the repository.
# Neither names where it resolves to: that path is the outside file, and the
# report is not the place to learn it.
_OUTSIDE_NOT_LINTED = (
    "not linted because it links to a file outside the repository (refused "
    "rather than read), so the services Compose would load from it were not "
    "graded."
)
_OUTSIDE_NOT_MERGED = (
    "not merged because it links to a file outside the repository (refused "
    "rather than read), so what Compose would merge from it was not graded."
)


@dataclass(frozen=True)
class DocumentGroup:
    """One project: the file a run reports against, plus what merges into it."""

    primary: str
    overlays: tuple[str, ...] = ()
    # Why the overlays are being merged. The report has to say, and the two
    # reasons are not interchangeable: a discovered override is merged
    # "because Compose merges it automatically", which is exactly the sentence
    # that was false when a COMPOSE_FILE was in play.
    selected_by_env: bool = False

    @property
    def paths(self) -> list[str]:
        """Every document in merge order, base first."""
        return [self.primary, *self.overlays]


@dataclass(frozen=True)
class Selection:
    """What a run will grade, and what it should say about how it decided."""

    groups: tuple[DocumentGroup, ...] = ()
    consumed: frozenset[str] = frozenset()
    notes: tuple[str, ...] = field(default=())
    # Every `.env` that will be read for this run, so the header can say so.
    # ADR-026 §5: a read that is announced is the declared input ADR-023
    # clause 2 permits; an unannounced one is the kind it forbids, and it is
    # also what makes a laptop-versus-CI difference a diff rather than a
    # mystery.
    env_files: tuple[str, ...] = ()
    # `(file, message)` for an input that was refused or unreadable, so what
    # it supplies was not graded: a `.env` that exists but could not be read,
    # or a `COMPOSE_FILE` list that was refused. These are coverage gaps, not
    # notes — the run exits 2 unless the gap is accepted — because Compose
    # still deploys what that input sets (P5: what could not be read fails
    # closed).
    gaps: tuple[tuple[str, str], ...] = ()

    def is_consumed(self, path: str) -> bool:
        """Whether ``path`` is already being graded inside another group."""
        return _key(path) in self.consumed


def _key(path: str | Path) -> str:
    """A stable identity for a path, so the same file is not graded twice.

    Lexical only: ``..`` and ``.`` segments are collapsed so ``compose.yml``
    and ``../dir1/compose.yml`` named from inside ``dir1`` are one document,
    but symlinks are not followed — ADR-023 keys everything a run does off
    the path as written, and ``resolve()`` would change that.
    """
    return os.path.normpath(Path(path).absolute())


def plan_documents(
    files: Iterable[str],
    *,
    read_env_files: bool = True,
    merge_overrides: bool = True,
) -> Selection:
    """Group ``files`` into the projects Compose would load them as.

    ``files`` empty means discovery, which is the bare ``compose-lint check``
    case. ``read_env_files=False`` is ``--no-env`` and reproduces the previous
    behaviour exactly; ``merge_overrides=False`` is ``--no-merge-overrides``.
    """
    named = list(files)
    if not named:
        return _plan_discovered(
            Path(), read_env_files=read_env_files, merge_overrides=merge_overrides
        )
    return _plan_named(
        named, read_env_files=read_env_files, merge_overrides=merge_overrides
    )


def _plan_discovered(
    directory: Path, *, read_env_files: bool, merge_overrides: bool
) -> Selection:
    """Discovery: no file was named, so ``COMPOSE_FILE`` may replace it wholly.

    This is the one path where honouring ``COMPOSE_FILE`` can *reduce* what is
    graded, and it is safe there precisely because nothing was named — the user
    asked "what does this project lint to", and the project's own answer is the
    file list Compose would load.
    """
    selected, notes, gaps = _compose_file_entries(
        directory, read_env_files=read_env_files
    )
    env_file = env_file_for(directory, read_env_files=read_env_files)
    env_files = (env_file,) if env_file else ()
    if selected is not None:
        return Selection(
            groups=(
                DocumentGroup(selected[0], tuple(selected[1:]), selected_by_env=True),
            ),
            consumed=frozenset(_key(path) for path in selected[1:]),
            notes=tuple(notes),
            env_files=env_files,
            gaps=tuple(gaps),
        )
    discovered = []
    for name in COMPOSE_FILENAMES:
        candidate = directory / name
        if not candidate.is_file():
            continue
        if _links_outside(candidate):
            gaps.append((str(candidate), _OUTSIDE_NOT_LINTED))
            continue
        discovered.append(name)
    selection = _pair_with_overrides(discovered, merge_overrides, notes, gaps)
    return replace(
        selection,
        env_files=env_files if discovered else (),
        gaps=tuple(gaps),
    )


def _plan_named(
    named: list[str], *, read_env_files: bool, merge_overrides: bool
) -> Selection:
    """Explicit paths: ``COMPOSE_FILE`` may add documents, never remove one."""
    groups: list[DocumentGroup] = []
    consumed: set[str] = set()
    notes: list[str] = []
    gaps: list[tuple[str, str]] = []
    planned: set[str] = set()
    env_files: list[str] = []

    for path in named:
        if _key(path) in planned:
            continue
        if _links_outside(Path(path)):
            gap = (path, _OUTSIDE_NOT_LINTED)
            if gap not in gaps:
                gaps.append(gap)
            continue
        directory = Path(path).parent
        selected, file_notes, file_gaps = _compose_file_entries(
            directory, read_env_files=read_env_files
        )
        # Two files in one directory share its `.env`; say so once.
        notes.extend(note for note in file_notes if note not in notes)
        gaps.extend(gap for gap in file_gaps if gap not in gaps)
        env_file = env_file_for(directory, read_env_files=read_env_files)
        if env_file is not None and env_file not in env_files:
            env_files.append(env_file)

        if selected is None:
            group = _with_override(path, merge_overrides, gaps)
        elif any(_key(entry) == _key(path) for entry in selected):
            # The project the .env describes contains this file, so grade the
            # project. Merge order is COMPOSE_FILE's, not the order the paths
            # happened to arrive in.
            group = DocumentGroup(
                selected[0], tuple(selected[1:]), selected_by_env=True
            )
        else:
            # ADR-026 §4: the named file is not in the project's own list, so
            # something disagrees. Grade what was asked for, and say so rather
            # than silently dropping it.
            notes.append(
                f"{path}: COMPOSE_FILE in {ENV_FILENAME} does not include this "
                "file, so it was graded on its own. Nothing was skipped."
            )
            group = _with_override(path, merge_overrides, gaps)

        groups.append(group)
        planned.update(_key(entry) for entry in group.paths)
        consumed.update(_key(entry) for entry in group.overlays)

    return Selection(
        groups=tuple(groups),
        consumed=frozenset(consumed),
        notes=tuple(notes),
        env_files=tuple(env_files),
        gaps=tuple(gaps),
    )


def _pair_with_overrides(
    discovered: list[str],
    merge_overrides: bool,
    notes: list[str],
    gaps: list[tuple[str, str]],
) -> Selection:
    """The pre-ADR-026 behaviour: each base file plus its sibling override."""
    groups = [_with_override(path, merge_overrides, gaps) for path in discovered]
    consumed = {_key(entry) for group in groups for entry in group.overlays}
    return Selection(
        groups=tuple(groups), consumed=frozenset(consumed), notes=tuple(notes)
    )


def _links_outside(path: Path) -> bool:
    """Whether ``path`` is a link to a file outside the run's reach.

    A primary Compose file and its sibling override arrive as paths, but a path
    is not always something a person chose. Bare discovery finds the file in
    the checkout, the Action's default list and ``pattern:`` do the same, and a
    list of changed files passed to ``files:`` or by pre-commit is whatever the
    change under review committed. A ``compose.yml`` committed as a symlink to
    a file elsewhere on the machine is then content choosing what the linter
    opens, and its values reach findings.

    So the test is on the link, not on who handed the path over. A plain path
    resolves to itself and is read as given, wherever it is. A link is followed
    while its target stays inside the repository that holds it (ADR-038): a
    target there is content the change under review can already see, so
    reading it discloses nothing, and a shared file symlinked into a monorepo's
    service directories is graded as Compose deploys it. Anything else is
    refused. Symlinked directories *above* the file resolve the same on both
    sides, so a checkout under a linked home directory is unaffected.

    The same rule holds for every other file a run opens
    (:func:`~compose_lint._safe_read.out_of_reach`); here the site's own root
    is the link's directory, widened to its repository there.
    """
    if not path.is_file():
        return False
    return out_of_reach(path, path.parent)


def _with_override(
    path: str, merge_overrides: bool, gaps: list[tuple[str, str]]
) -> DocumentGroup:
    """Pair ``path`` with the overlay Compose would merge into it, if any.

    The override is always found, never named, so it is contained like any
    other file the project chooses: one resolving outside the base file's
    directory is not merged, and ``gaps`` gets the reason.
    """
    if not merge_overrides:
        return DocumentGroup(path)
    base = Path(path)
    if base.name not in COMPOSE_FILENAMES:
        return DocumentGroup(path)
    present = [
        base.parent / name for name in OVERRIDE_SEARCH if (base.parent / name).is_file()
    ]
    if not present:
        return DocumentGroup(path)
    candidate = present[0]
    if _links_outside(candidate):
        gap = (str(candidate), _OUTSIDE_NOT_MERGED)
        if gap not in gaps:
            gaps.append(gap)
        return DocumentGroup(path)
    return DocumentGroup(path, (str(candidate),))


def env_file_for(directory: Path, *, read_env_files: bool) -> str | None:
    """The ``.env`` that will be read for ``directory``, if there is one."""
    if not read_env_files:
        return None
    candidate = directory / ENV_FILENAME
    return str(candidate) if candidate.is_file() else None


def _compose_file_entries(
    directory: Path, *, read_env_files: bool
) -> tuple[list[str] | None, list[str], list[tuple[str, str]]]:
    """The document list ``directory``'s ``.env`` selects, and what to say.

    The third value is the coverage gaps, as ``(file, message)``: a refused
    list, or a ``.env`` that could not be read. They are not repeated in the
    notes; the caller reports them on the gap channel.

    ``None`` means no list applies — there is no ``.env``, it sets no
    ``COMPOSE_FILE``, or the one it sets was refused. A refusal falls back to
    the default behaviour rather than honouring part of the list, because a
    partially-honoured ``COMPOSE_FILE`` grades a set Compose never loads, which
    is the failure this whole mechanism exists to remove.
    """
    if not read_env_files:
        return None, [], []
    parsed = read_env(directory, COMPOSE_FILE_KEYS, within=directory)
    if parsed is None:
        failure = env_read_failure(directory, within=directory)
        if failure is None:
            return None, [], []
        message = (
            f"not read because {failure}, so it selected no "
            "documents and supplied no values. Compose reads it anyway, so any "
            "value it sets was not graded."
        )
        return None, [], [(str(directory / ENV_FILENAME), message)]
    raw = parsed.values.get("COMPOSE_FILE")
    if not raw:
        return None, [], []

    separator = parsed.values.get("COMPOSE_PATH_SEPARATOR") or DEFAULT_PATH_SEPARATOR
    entries = [part for part in raw.split(separator) if part.strip()]
    resolved: list[str] = []
    for entry in entries:
        candidate = _resolve_entry(directory, entry.strip())
        if candidate is None:
            message = (
                f"COMPOSE_FILE names {entry.strip()!r}, which leaves the project "
                "directory, links outside the repository, or is missing, so the "
                "whole list was ignored and file selection fell back to the "
                "default."
            )
            return None, [], [(str(directory / ENV_FILENAME), message)]
        resolved.append(candidate)
    if not resolved:
        return None, [], []

    note = (
        f"{directory / ENV_FILENAME}: COMPOSE_FILE selects "
        f"{', '.join(Path(path).name for path in resolved)}"
    )
    if len(resolved) > 1:
        note += ", merged in that order"
    return resolved, [note + "."], []


def _resolve_entry(directory: Path, entry: str) -> str | None:
    """Resolve one ``COMPOSE_FILE`` entry, or ``None`` if it must be refused.

    Refused when the entry is absolute, when it climbs out of the project
    directory, or when no such file exists. The first two are the traversal
    guard ADR-026 §4 requires: the ``.env`` is content inside the artifact being
    linted, and a list that reaches outside the project would let it choose what
    the linter opens. The third is refused because Compose fails on it too — a
    project whose ``COMPOSE_FILE`` names a file that is not there does not start.

    The climb test is lexical and POSIX-spelled, matching ADR-023 §1: whether an
    entry escapes is a property of what it says, not of the lint host's
    filesystem, and resolving it physically would follow the lint host's
    symlinks to answer a question about the project.
    """
    if os.path.isabs(entry) or (len(entry) > 1 and entry[1] == ":"):
        return None  # absolute POSIX path, or a Windows drive-qualified one
    parts: list[str] = []
    for part in PurePosixPath(entry.replace("\\", "/")).parts:
        if part == "..":
            if not parts:
                return None  # climbs out of the project directory
            parts.pop()
        elif part not in (".", ""):
            parts.append(part)
    if not parts:
        return None
    candidate = directory.joinpath(*parts)
    if not candidate.is_file():
        return None
    # Second gate, on this filesystem rather than on the spelling. The climb
    # test above is deliberately lexical (ADR-023 §1), and a symlink is
    # invisible to it: a committed link named like a project-relative document
    # passes every test above while pointing anywhere on the runner. Selecting
    # one would let the artifact choose a file outside itself, which is the
    # traversal ADR-026 §4 requires this function to refuse. A link into the
    # repository stays inside the checkout and is followed (`out_of_reach`).
    if out_of_reach(candidate, directory):
        return None
    return str(candidate)
