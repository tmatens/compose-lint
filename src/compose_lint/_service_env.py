"""Resolve and read the ``env_file:`` targets a service names.

Where :mod:`compose_lint._env_file` knows the *grammar* of an env file, this
module knows which ones a document points at, whether compose-lint will open
them, and what the result contributes to a service's process environment. It is
the file-selection half of
[ADR-027](../../docs/adr/027-grade-env-file-where-the-document-routes-it.md).

Compose's own behaviour was derived from the binary (5.4.0) and is followed
except where the ADR says otherwise:

===========================  ==========================================
written                      Compose
===========================  ==========================================
``env_file: app.env``        read, relative to the Compose file's parent
``env_file: [a.env, b.env]`` read in order; later wins
``path:`` / ``required:``    the mapping spelling; missing + required aborts
``format: raw``              a different grammar (see ``_env_file``)
``env_file: ["${W}.env"]``   the path interpolates, from ``.env``
``env_file: ../out.env``     read
``env_file: /etc/app.env``   read
``environment:``             wins over every ``env_file:`` key
===========================  ==========================================

Two of those rows are deliberately not followed. A path that leaves the project
directory is refused rather than read (ADR-027 §7): Compose reads it, but an
``env_file: /home/runner/.aws/credentials`` added in a pull request would put
lint-host key *names* into a report through the one field the credential rules
emit, which is the leak ADR-023 exists to prevent. And an absent file is a note
rather than a fatal error, because compose-lint is not the thing being started —
though what the note *says* differs by ``required:``, since only one of the two
means the project cannot deploy.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

from compose_lint._env_file import (
    MAX_ENV_BYTES,
    env_file_references,
    parse_env_file,
    read_env,
)
from compose_lint._safe_read import (
    UnsafeFileError,
    escapes_project,
    read_text_bounded,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

__all__ = [
    "EnvFileKey",
    "EnvFileRef",
    "ServiceEnvFiles",
    "SkippedLines",
    "Unread",
    "UnreadEnvFile",
    "describe_unread",
    "env_file_refs",
    "resolve_env_files",
]


class Unread(Enum):
    """Why a named ``env_file:`` did not contribute anything."""

    #: The path still carries a ``${VAR}`` nothing supplied, so it names no file.
    UNRESOLVED_PATH = "unresolved-path"
    #: The path resolves outside the project directory (ADR-027 §7).
    OUTSIDE_PROJECT = "outside-project"
    #: Named, inside the project, and not there. Compose aborts when required.
    ABSENT = "absent"
    #: Present but unreadable: over the byte cap, undecodable, a FIFO, a device.
    UNREADABLE = "unreadable"


@dataclass(frozen=True)
class EnvFileRef:
    """One ``env_file:`` target as the document writes it."""

    path: str
    required: bool
    raw: bool


@dataclass(frozen=True)
class EnvFileKey:
    """One key an ``env_file:`` contributes to a service's environment."""

    key: str
    value: str
    #: The file as the document wrote it, which is what a report should name —
    #: not the lint host's absolute path, which is not a fact about the project.
    source_file: str
    #: 1-indexed line within that file.
    line: int


@dataclass(frozen=True)
class UnreadEnvFile:
    """A target that was named but contributed nothing, and why."""

    path: str
    reason: Unread
    required: bool


@dataclass(frozen=True)
class SkippedLines:
    """Lines in a target that are not entries, and that Compose calls fatal."""

    path: str
    lines: tuple[int, ...]


@dataclass(frozen=True)
class ServiceEnvFiles:
    """What one service's ``env_file:`` targets contribute.

    ``keys`` is what actually reaches the container: files applied in written
    order with a later one winning, and anything the service's own
    ``environment:`` also sets removed, because Compose's precedence means such
    a key contributes nothing (verified). Dropping it here is also what keeps
    CL-0020 from reporting the same credential twice — it already grades the
    ``environment:`` spelling.
    """

    keys: tuple[EnvFileKey, ...]
    unread: tuple[UnreadEnvFile, ...]
    skipped: tuple[SkippedLines, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.keys or self.unread or self.skipped)


def env_file_refs(value: Any) -> list[EnvFileRef]:
    """Every target an ``env_file:`` names, in written order.

    Three spellings are legal and all three appear in the corpus: a bare string,
    a list of strings, and a list of mappings carrying ``path:`` alongside
    ``required:`` / ``format:``. The mapping form is the newer one and is the
    easiest to miss — 29 corpus files use it, and reading only the string forms
    would report a service as covered precisely where the author reached for the
    more explicit syntax.
    """
    if isinstance(value, str):
        return [EnvFileRef(path=value, required=True, raw=False)] if value else []
    if not isinstance(value, list):
        return []
    refs: list[EnvFileRef] = []
    for entry in value:
        if isinstance(entry, str) and entry:
            refs.append(EnvFileRef(path=entry, required=True, raw=False))
        elif isinstance(entry, dict):
            path = entry.get("path")
            if isinstance(path, str) and path:
                refs.append(
                    EnvFileRef(
                        path=path,
                        required=entry.get("required", True) is not False,
                        raw=entry.get("format") == "raw",
                    )
                )
    return refs


def _project_relative(path: str) -> list[str] | None:
    """``path`` as cleaned segments under the project, or ``None`` if it leaves.

    Segment math, never the lint host's path semantics: whether a document
    reaches outside its own project is a fact about the document, and ADR-023
    requires it to read the same on every platform. A leading ``/``, a drive
    letter, a ``~``, or any ``..`` that climbs past the start all leave.

    Cleaning is lexical and happens before anything touches the filesystem,
    because Compose's is too: ``conf/../app.env`` reads ``app.env`` even when
    ``conf`` does not exist (verified against Compose 5.4.0). Joining the
    uncleaned path instead would have reported that file absent on POSIX, where
    the kernel resolves ``..`` component by component.
    """
    if path.startswith(("/", "~", "\\\\")) or (len(path) > 1 and path[1] == ":"):
        return None
    segments: list[str] = []
    for segment in path.replace("\\", "/").split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if not segments:
                return None
            segments.pop()
            continue
        segments.append(segment)
    return segments or None


def _classify(ref: EnvFileRef, base_dir: Path) -> tuple[Path | None, Unread | None]:
    """The lint-host path to open, or why there is not one."""
    if "$" in ref.path:
        # Anything the document or its `.env` could supply is already
        # substituted by the time this runs, so a surviving `$` means the name
        # is unknowable from the files (ADR-026 divergence 1).
        return None, Unread.UNRESOLVED_PATH
    segments = _project_relative(ref.path)
    if segments is None:
        return None, Unread.OUTSIDE_PROJECT
    candidate = base_dir.joinpath(*segments)
    # Second gate, and a different question. The segment math above rules on
    # what the *document* says, identically on every platform (ADR-023 §1); a
    # symlink says nothing. `probe.env` is spelled like a project-relative
    # file and passes every lexical test while the committed link beside it
    # points at `/home/runner/.aws/credentials` — the scenario ADR-027 §7
    # names and promises to refuse. Asked here, at the moment of resolution,
    # about this filesystem.
    if escapes_project(candidate, base_dir):
        return None, Unread.OUTSIDE_PROJECT
    return candidate, None


def resolve_env_files(
    data: dict[str, Any],
    base_dir: Path,
) -> dict[str, ServiceEnvFiles]:
    """Read every service's ``env_file:`` targets, keyed by service name.

    Services naming no target are absent from the result rather than present and
    empty, so a caller can ask the cheap question first.

    The sibling ``.env`` is read for exactly the names the env files chain to,
    and no others. Compose resolves an ``env_file:`` value against the ``.env``,
    so those names have to be in scope; reading the ``.env`` in full to supply
    them would quietly retire ADR-026 §5's retention guarantee, so the env files
    are scanned for their references first and the ``.env`` read is narrowed to
    those.

    ``--no-env`` is handled by not calling this at all, rather than by a flag
    here: it means "do not read the env files beside this one", and an
    ``env_file:`` target read while the ``.env`` went unread would be a third
    behaviour nobody asked for.
    """
    services = data.get("services")
    if not isinstance(services, dict):
        return {}

    plans: dict[str, list[tuple[EnvFileRef, Path | None, Unread | None]]] = {}
    texts: dict[Path, str | None] = {}
    for name, config in services.items():
        if not isinstance(config, dict):
            continue
        refs = env_file_refs(config.get("env_file"))
        if not refs:
            continue
        plan = []
        for ref in refs:
            path, refusal = _classify(ref, base_dir)
            if path is not None and path not in texts:
                texts[path] = _read_text(path)
            plan.append((ref, path, refusal))
        plans[name] = plan
    if not plans:
        return {}

    supplied = _dotenv_scope(plans, texts, base_dir)

    resolved: dict[str, ServiceEnvFiles] = {}
    for name, plan in plans.items():
        config = services[name]
        resolved[name] = _resolve_one(plan, texts, supplied, config)
    return resolved


def _read_text(path: Path) -> str | None:
    """The file's text, or ``None`` when it cannot be read.

    Absent and unreadable are separated by the caller, which tests the path;
    here they collapse, because the byte cap and the safe-read guard are the
    same in both cases.
    """
    try:
        return read_text_bounded(path, max_bytes=MAX_ENV_BYTES)
    except (FileNotFoundError, UnsafeFileError, UnicodeDecodeError, OSError):
        return None


def _dotenv_scope(
    plans: dict[str, list[tuple[EnvFileRef, Path | None, Unread | None]]],
    texts: dict[Path, str | None],
    base_dir: Path,
) -> Mapping[str, str]:
    """The ``.env`` values the env files chain to, and nothing else."""
    wanted: set[str] = set()
    for plan in plans.values():
        for ref, path, _refusal in plan:
            text = texts.get(path) if path is not None else None
            if text is not None:
                wanted |= env_file_references(text, raw=ref.raw)
    if not wanted:
        return {}
    parsed = read_env(base_dir, wanted)
    return parsed.values if parsed is not None else {}


def _resolve_one(
    plan: list[tuple[EnvFileRef, Path | None, Unread | None]],
    texts: dict[Path, str | None],
    supplied: Mapping[str, str],
    config: dict[str, Any],
) -> ServiceEnvFiles:
    """Apply one service's targets in order, then remove what it overrides."""
    scope: dict[str, str] = dict(supplied)
    contributed: dict[str, EnvFileKey] = {}
    unread: list[UnreadEnvFile] = []
    skipped: list[SkippedLines] = []

    for ref, path, refusal in plan:
        if refusal is not None or path is None:
            unread.append(
                UnreadEnvFile(ref.path, refusal or Unread.UNRESOLVED_PATH, ref.required)
            )
            continue
        text = texts.get(path)
        if text is None:
            reason = Unread.ABSENT if not path.exists() else Unread.UNREADABLE
            unread.append(UnreadEnvFile(ref.path, reason, ref.required))
            continue
        parsed = parse_env_file(text, defined=scope, raw=ref.raw)
        if parsed.skipped_lines:
            skipped.append(SkippedLines(ref.path, parsed.skipped_lines))
        for key, value in parsed.values.items():
            scope[key] = value
            contributed[key] = EnvFileKey(
                key=key,
                value=value,
                source_file=ref.path,
                line=parsed.lines.get(key, 0),
            )

    for key in _environment_keys(config.get("environment")):
        contributed.pop(key, None)

    return ServiceEnvFiles(
        keys=tuple(contributed.values()),
        unread=tuple(unread),
        skipped=tuple(skipped),
    )


def _environment_keys(env_block: Any) -> set[str]:
    """Every key the service's own ``environment:`` sets, in either spelling.

    A bare ``KEY`` in the list form counts: Compose sources it from its own
    environment, and that still takes precedence over an ``env_file:`` value
    (the key is set either way, just not from the file).
    """
    keys: set[str] = set()
    if isinstance(env_block, dict):
        keys |= {key for key in env_block if isinstance(key, str)}
    elif isinstance(env_block, list):
        for item in env_block:
            if isinstance(item, str):
                keys.add(item.split("=", 1)[0])
            elif isinstance(item, dict):
                keys |= {key for key in item if isinstance(key, str)}
    return keys


def describe_unread(resolved: Mapping[str, ServiceEnvFiles]) -> list[str]:
    """One stderr note per target that contributed nothing, per service.

    Replaces the blanket note #669 shipped, which said the credential rules
    "were not evaluated" for *every* service naming an ``env_file:`` because
    none was opened. Most now are, so the note has to say which target was
    missed and why — a note that fires beside the findings it claims are
    missing is worse than no note at all.

    The wording distinguishes the two absent cases, which is the first of the
    two questions ADR-027 left open. Only a *required* target's absence means
    the project cannot deploy — ``docker compose config`` exits 1 — and only
    then is there a configuration compose-lint failed to grade. An optional
    target's absence is the deployed configuration, so the note states what
    Compose does and claims no missed evaluation.

    A skipped line gets a note too, and that settles the second question
    ADR-027 left open. Compose refuses a whole env file over one malformed line
    and starts nothing; compose-lint keeps the well-formed entries, because
    refusing the file would drop real findings for every other key — a silent
    false negative, traded for a file the user's next ``docker compose up``
    will reject anyway. ADR-026 §5 justified the same leniency for a ``.env`` on
    grounds that no longer hold here (every key is wanted now, §4), so the
    leniency is kept on its own merits and stated rather than inferred.

    Notes never touch the exit code, like the unread-``.env`` and
    unresolved-mount-source notes they sit beside.
    """
    unevaluated = "so CL-0020 and CL-0021 were not evaluated for its keys"
    notes: list[str] = []
    for service in sorted(resolved):
        for entry in resolved[service].unread:
            path = repr(entry.path)
            if entry.reason is Unread.ABSENT and entry.required:
                notes.append(
                    f"service '{service}' reads {path}, which is not present. "
                    "Compose refuses to start a project whose required "
                    f"env_file is missing, {unevaluated}"
                )
            elif entry.reason is Unread.ABSENT:
                notes.append(
                    f"service '{service}' reads {path}, which is not present "
                    "and not required. Compose starts the service without it, "
                    "which is the configuration graded here"
                )
            elif entry.reason is Unread.UNREADABLE:
                notes.append(
                    f"service '{service}' reads {path}, which could not be "
                    f"read, {unevaluated}"
                )
            elif entry.reason is Unread.OUTSIDE_PROJECT:
                notes.append(
                    f"service '{service}' reads {path}, which resolves outside "
                    f"the project directory and is not opened, {unevaluated}"
                )
            else:
                notes.append(
                    f"service '{service}' reads {path}, whose path is still "
                    f"unresolved and names no file, {unevaluated}"
                )
        for skip in resolved[service].skipped:
            numbers = ", ".join(str(number) for number in skip.lines)
            plural = "lines" if len(skip.lines) > 1 else "line"
            notes.append(
                f"service '{service}' reads {skip.path!r}, whose {plural} "
                f"{numbers} could not be read as KEY=value. Compose refuses a "
                "whole env file over one such line; the remaining entries were "
                "graded"
            )
    return notes
