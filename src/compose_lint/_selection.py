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

from compose_lint._env_file import ENV_FILENAME, read_env

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
# Compose pairs the spelling: `compose.yml` takes `compose.override.yml`, and
# `docker-compose.yaml` takes `docker-compose.override.yaml`.
OVERRIDE_FILENAMES = {
    "compose.yml": "compose.override.yml",
    "compose.yaml": "compose.override.yaml",
    "docker-compose.yml": "docker-compose.override.yml",
    "docker-compose.yaml": "docker-compose.override.yaml",
}

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

    def is_consumed(self, path: str) -> bool:
        """Whether ``path`` is already being graded inside another group."""
        return _key(path) in self.consumed


def _key(path: str | Path) -> str:
    """A stable identity for a path, so the same file is not graded twice."""
    return str(Path(path).absolute())


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
    selected, notes = _compose_file_entries(directory, read_env_files=read_env_files)
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
        )
    discovered = [name for name in COMPOSE_FILENAMES if (directory / name).is_file()]
    selection = _pair_with_overrides(discovered, merge_overrides, notes)
    return replace(selection, env_files=env_files if discovered else ())


def _plan_named(
    named: list[str], *, read_env_files: bool, merge_overrides: bool
) -> Selection:
    """Explicit paths: ``COMPOSE_FILE`` may add documents, never remove one."""
    groups: list[DocumentGroup] = []
    consumed: set[str] = set()
    notes: list[str] = []
    planned: set[str] = set()
    env_files: list[str] = []

    for path in named:
        if _key(path) in planned:
            continue
        directory = Path(path).parent
        selected, file_notes = _compose_file_entries(
            directory, read_env_files=read_env_files
        )
        notes.extend(file_notes)
        env_file = env_file_for(directory, read_env_files=read_env_files)
        if env_file is not None and env_file not in env_files:
            env_files.append(env_file)

        if selected is None:
            group = _with_override(path, merge_overrides)
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
            group = _with_override(path, merge_overrides)

        groups.append(group)
        planned.update(_key(entry) for entry in group.paths)
        consumed.update(_key(entry) for entry in group.overlays)

    return Selection(
        groups=tuple(groups),
        consumed=frozenset(consumed),
        notes=tuple(notes),
        env_files=tuple(env_files),
    )


def _pair_with_overrides(
    discovered: list[str], merge_overrides: bool, notes: list[str]
) -> Selection:
    """The pre-ADR-026 behaviour: each base file plus its sibling override."""
    groups = [_with_override(path, merge_overrides) for path in discovered]
    consumed = {_key(entry) for group in groups for entry in group.overlays}
    return Selection(
        groups=tuple(groups), consumed=frozenset(consumed), notes=tuple(notes)
    )


def _with_override(path: str, merge_overrides: bool) -> DocumentGroup:
    """Pair ``path`` with the overlay Compose would merge into it, if any."""
    if not merge_overrides:
        return DocumentGroup(path)
    base = Path(path)
    override_name = OVERRIDE_FILENAMES.get(base.name)
    if override_name is None:
        return DocumentGroup(path)
    candidate = base.parent / override_name
    if not candidate.is_file():
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
) -> tuple[list[str] | None, list[str]]:
    """The document list ``directory``'s ``.env`` selects, and what to say.

    ``None`` means no list applies — there is no ``.env``, it sets no
    ``COMPOSE_FILE``, or the one it sets was refused. A refusal falls back to
    the default behaviour rather than honouring part of the list, because a
    partially-honoured ``COMPOSE_FILE`` grades a set Compose never loads, which
    is the failure this whole mechanism exists to remove.
    """
    if not read_env_files:
        return None, []
    parsed = read_env(directory, COMPOSE_FILE_KEYS)
    if parsed is None:
        return None, []
    raw = parsed.values.get("COMPOSE_FILE")
    if not raw:
        return None, []

    separator = parsed.values.get("COMPOSE_PATH_SEPARATOR") or DEFAULT_PATH_SEPARATOR
    entries = [part for part in raw.split(separator) if part.strip()]
    resolved: list[str] = []
    for entry in entries:
        candidate = _resolve_entry(directory, entry.strip())
        if candidate is None:
            return None, [
                f"{directory / ENV_FILENAME}: COMPOSE_FILE names {entry.strip()!r}, "
                "which is outside the project directory or missing, so the whole "
                "list was ignored and file selection fell back to the default."
            ]
        resolved.append(candidate)
    if not resolved:
        return None, []

    note = (
        f"{directory / ENV_FILENAME}: COMPOSE_FILE selects "
        f"{', '.join(Path(path).name for path in resolved)}"
    )
    if len(resolved) > 1:
        note += ", merged in that order"
    return resolved, [note + "."]


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
    return str(candidate)
