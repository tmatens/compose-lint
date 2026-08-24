"""Read the ``.env`` Compose reads beside a Compose file.

Compose loads a ``.env`` from the *project directory* — the first Compose
file's parent, not the shell's working directory — and uses it for two
unrelated jobs: supplying interpolation values, and (via ``COMPOSE_FILE``)
choosing which documents get loaded at all. compose-lint reads it for the same
two reasons, under [ADR-026](../../docs/adr/026-read-the-sibling-env-file.md):
*use files as Docker Compose would, when run in that file's directory.*

Every rule below was derived from ``docker compose config`` (Compose 5.4.0,
client-side, no daemon) rather than from the format's prose, because the
``.env`` grammar is godotenv's and is nowhere normatively specified for
Compose. The table is the contract:

==========================  ==========================  ====================
written                     Compose ships               note
==========================  ==========================  ====================
``K=v``                     ``v``
``K = v``                   ``v``                       key and value trimmed
``export K=v``              ``v``                       prefix consumed
``K="v w"``                 ``v w``                     quotes stripped
``K='v w'``                 ``v w``                     quotes stripped
``K=v # trail``             ``v``                       unquoted: comment
``K="v # trail"``           ``v # trail``               quoted: literal
``K=``                      empty
``K``                       empty                       key with no ``=``
``K=a=b``                   ``a=b``                     first ``=`` splits
``K=first`` then ``K=…``    last one wins
``K="a\\nb"``                ``a``/newline/``b``          double: escapes
``K='a\\nb'``                ``a\\nb``                    single: literal
``K=a\\nb``                  ``a\\nb``                    unquoted: literal
``A=one`` / ``K=${A}-two``  ``one-two``                 expands, in order
``A=one`` / ``K=$A-two``    ``one-two``                 bare form too
``K='${A}'``                ``${A}``                    single: no expansion
``K=${LATER}`` first        empty                       **no forward refs**
``K=${MISSING:-d}``         ``d``                       defaults apply
``K=a$$b``                  ``a$b``                     ``$$`` escapes a dollar
==========================  ==========================  ====================

The values returned are what Compose *ships*, not how ``docker compose config``
prints them. That command re-escapes a literal dollar on output so its own
document round-trips — a value of ``a$b`` is printed ``a$$b`` — so a caller
comparing against ``config`` output has to decode it, and a caller injecting one
of these values into a document must not run interpolation over it again.

Two deliberate divergences from Compose, both required by ADR-026:

1. **No process-environment fallback.** Compose resolves a reference it cannot
   find in the ``.env`` against the shell, so a ``.env`` carrying
   ``DATA=${HOME}/data`` imports the lint host's environment — the exact
   leak [ADR-023](../../docs/adr/023-deploy-host-independent-claims.md)
   forbids, arriving through a file rather than through an env lookup. Such a
   value is reported *unresolved* rather than resolved against this machine, so
   the rule that would have consumed it stays silent. Conservative in the same
   direction the parser already takes for a defaultless ``${VAR}``.

2. **Malformed lines are skipped, not fatal.** Compose refuses the whole file
   (``failed to read .env: line 1: key cannot contain a space``) and starts
   nothing. compose-lint is not the thing being started, and failing a lint run
   over a stray line in a file the user did not ask us to lint trades a report
   for nothing. Skipped lines are recorded so a caller can say so.

Only the values a run actually needs are kept, per ADR-026 §5. The bytes are
still scanned — there is no seeking to one key — so the honest claim is that
values the run does not need are discarded rather than parsed into it, never
that the file is not read.

The module also reads the *other* env file: an ``env_file:`` target, named in
the document rather than found beside it, under
[ADR-027](../../docs/adr/027-grade-env-file-where-the-document-routes-it.md).
The grammar is godotenv's both times, which is why one scanner serves both, but
the two readers are not interchangeable and :func:`parse_env_file` is separate
for three reasons, each derived from the binary the same way:

1. **A bare ``KEY`` means different things.** A ``.env`` ships it empty; an
   ``env_file:`` treats it as a lookup in Compose's own process environment and
   omits the key when that is unset. So it is reported unresolved rather than
   empty — claiming the empty string would be claiming a lint-host fact.
2. **``format: raw`` exists only here**, and is a different grammar rather than
   a relaxed one: no ``export`` prefix, no trimming, no quote or comment
   processing, no interpolation.
3. **Nothing is filtered by wantedness.** Every key in an ``env_file:`` lands in
   a named service's process environment, so every key is one a rule may grade
   (ADR-027 §4). The §5 retention claim above does not extend to these files,
   and the honest statement for them is that every key is examined.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from compose_lint._limits import MAX_SUBSTITUTED_LEN
from compose_lint._safe_read import UnsafeFileError, read_text_bounded
from compose_lint.rules._interpolation import _default_of, _matching_brace

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from pathlib import Path

__all__ = [
    "ENV_FILENAME",
    "EnvFile",
    "env_file_references",
    "parse_env",
    "parse_env_file",
    "read_env",
    "read_env_file",
]

ENV_FILENAME = ".env"

# A `.env` is a hand-written settings file, not a document. Compose's own is
# conventionally a few dozen lines; this bounds the pathological case well above
# anything real, and far below `_safe_read.MAX_FILE_BYTES`, because nothing here
# needs megabytes and the file is attacker-authorable in a pull request.
MAX_ENV_BYTES = 256 * 1024

# `export ` is consumed as a prefix, matching godotenv: the file is often
# `source`d by a shell as well, and the keyword is part of that idiom rather
# than part of the key.
_EXPORT_RE = re.compile(r"^\s*export\s+")

# A key Compose accepts. It rejects a key containing a space outright, which is
# how the malformed case above is detected; anchoring the whole name is a
# stricter test that also catches the empty key in a leading `=value`.
_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")

# An unquoted value ends at an unescaped `#`, which starts a trailing comment.
# Quoted values do not -- `K="v # trail"` keeps the hash.
_UNQUOTED_COMMENT_RE = re.compile(r"\s+#.*$")

# Escapes a double-quoted value processes. Single-quoted and unquoted values
# carry the backslash through literally (verified: `K=a\nb` ships `a\nb`).
_DOUBLE_QUOTE_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    '"': '"',
    "\\": "\\",
    "$": "$",
}


@dataclass(frozen=True)
class EnvFile:
    """What a ``.env`` supplies, narrowed to what the caller asked for.

    ``values`` carries only keys that resolved *and* were wanted. A key whose
    value referenced something this module will not resolve — an undefined name,
    a forward reference, or anything that would have come from the process
    environment — is named in ``unresolved`` instead, so a caller can tell
    "the file does not set this" from "the file sets this to something we
    decline to guess". Both mean the same thing to a rule (nothing to
    substitute); they differ in what the run can honestly say about coverage.
    """

    values: Mapping[str, str]
    unresolved: frozenset[str]
    skipped_lines: tuple[int, ...]
    # Where each resolved key was written, 1-indexed. Populated by
    # :func:`parse_env_file` and left empty by :func:`parse_env`, which has no
    # caller that needs it.
    lines: Mapping[str, int] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.values)


@dataclass(frozen=True)
class _Entry:
    """One ``KEY=value`` as written, before any expansion."""

    key: str
    raw: str
    expands: bool  # false for a single-quoted value
    # `KEY` with no `=` at all. The two files disagree about what that means:
    # a `.env` ships it empty, while an `env_file:` treats it as a lookup in
    # the process environment and omits the key entirely when it is unset
    # (both verified against Compose 5.4.0). Recorded here so one scanner can
    # serve both readers.
    bare: bool = False
    # 1-indexed line this entry was written on. Only the ``env_file:`` reader
    # keeps it: a finding about a key in one of those files points at the key
    # (ADR-027 §6), while a ``.env`` value is only ever reported through the
    # document position that consumed it.
    line: int = 0


def read_env(directory: Path, wanted: Iterable[str] | None = None) -> EnvFile | None:
    """Read ``directory/.env``, or ``None`` if there is not one.

    ``directory`` is the project directory — the Compose file's own parent,
    which is where Compose looks. A ``.env`` beside the *shell's* working
    directory is deliberately not consulted: verified that Compose ignores it
    when ``-f`` names a file elsewhere, and reading it would make the run depend
    on where it was launched from rather than on the project.

    An unreadable ``.env`` is treated as absent rather than fatal, for the same
    reason a malformed line is skipped: the file is not the artifact under
    lint, and a FIFO or an over-cap file committed as one should not take the
    report down with it.
    """
    path = directory / ENV_FILENAME
    try:
        text = read_text_bounded(path, max_bytes=MAX_ENV_BYTES)
    except (FileNotFoundError, UnsafeFileError, UnicodeDecodeError, OSError):
        return None
    return parse_env(text, wanted)


def parse_env(text: str, wanted: Iterable[str] | None = None) -> EnvFile:
    """Parse ``.env`` text, resolving only what ``wanted`` needs.

    ``wanted`` is the set of names the run will actually look up. ``None`` means
    all of them, which is what a test or an exploratory caller wants; a real run
    passes the fixed ``COMPOSE_*`` allowlist plus the names its Compose
    documents reference. Whatever is passed is closed over the ``.env``'s own
    references first, because a wanted value may be built from an unwanted one
    (``WANTED=${BASE}/docker.sock`` needs ``BASE``), and a filter applied before
    that closure would silently unresolve it.
    """
    entries, skipped = _scan(text)
    needed = _closure(entries, wanted)
    values, unresolved = _resolve(entries, needed)
    return EnvFile(
        values=values,
        unresolved=frozenset(unresolved),
        skipped_lines=tuple(skipped),
    )


def _split_env_lines(text: str) -> list[str]:
    """Split a ``.env`` the way Compose does: on ``\\n`` alone.

    Deliberately **not** ``str.splitlines()`` and not
    :func:`compose_lint._lines.split_lines`. Both break on more than Compose
    does, and here that is a correctness and a security problem rather than a
    style one. Probed against ``docker compose config``:

    ===========  =========================================================
    character    Compose
    ===========  =========================================================
    ``\\n``       line break
    ``\\r\\n``     line break (the ``\\r`` is trailing whitespace, trimmed)
    ``\\r``       **not** a break -- ``K=v\\rJ=w`` sets ``K`` to ``v\\rJ=w``
    ``\\f``       not a break
    U+0085       not a break
    U+2028       not a break
    ===========  =========================================================

    A splitter that breaks on any of the last four sees entries Compose never
    sees. That is the same failure the add-only rule in ADR-026 §4 exists to
    prevent, arriving by a different route: a ``.env`` carrying
    ``K=v\\rCOMPOSE_FILE=decoy.yml`` would offer compose-lint a ``COMPOSE_FILE``
    that Compose itself does not read.

    ``str.splitlines()`` is additionally banned in ``src/`` by
    ``tests/test_line_space_guard.py``, whose reasoning is about agreeing with
    PyYAML. A ``.env`` is not a YAML document and its authority is godotenv, so
    this agrees with that authority instead — and satisfies the guard by not
    calling ``splitlines`` at all.
    """
    return text.split("\n")


def _scan(text: str, *, raw: bool = False) -> tuple[list[_Entry], list[int]]:
    """Split text into entries as written, plus the lines that are not entries.

    Nothing is expanded here. Separating the scan from the resolution is what
    lets the closure be computed before any value is built, so an unwanted
    secret is never assembled — only its raw line is briefly in hand, which is
    unavoidable for any parser that has to find the key at all.
    """
    entries: list[_Entry] = []
    skipped: list[int] = []
    # `\ufeff` is a BOM on the first line; Compose tolerates one (verified), and
    # left in place it would become part of the first key.
    for number, line in enumerate(_split_env_lines(text.lstrip("\ufeff")), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if raw:
            # `format: raw` is a different grammar, not a relaxation of this
            # one: `export` is not a prefix (Compose rejects `export D=v` as a
            # key containing whitespace), nothing is trimmed, quotes and `#`
            # are payload, and `$$` is two literal dollars. Verified against
            # Compose 5.4.0, whose output for `A=v # trail` is `v # trail` and
            # for `F=  spaced  ` is `  spaced  `.
            key, separator, value = line.partition("=")
            if not separator or not _KEY_RE.match(key):
                skipped.append(number)
                continue
            entries.append(_Entry(key=key, raw=value, expands=False, line=number))
            continue
        stripped = _EXPORT_RE.sub("", stripped)
        key, separator, value = stripped.partition("=")
        key = key.strip()
        if not _KEY_RE.match(key):
            # Compose refuses the whole file here; see the module docstring for
            # why this does not.
            skipped.append(number)
            continue
        if not separator:
            entries.append(
                _Entry(key=key, raw="", expands=False, bare=True, line=number)
            )
            continue
        entries.append(_entry(key, value.strip(), number))
    return entries, skipped


def _entry(key: str, raw: str, line: int = 0) -> _Entry:
    """Build one entry, applying the quoting rules for its style."""
    if len(raw) >= 2 and raw[0] == raw[-1] == "'":
        return _Entry(key=key, raw=raw[1:-1], expands=False, line=line)
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        return _Entry(key=key, raw=_unescape(raw[1:-1]), expands=True, line=line)
    return _Entry(
        key=key, raw=_UNQUOTED_COMMENT_RE.sub("", raw), expands=True, line=line
    )


def _unescape(value: str) -> str:
    """Process the escapes a double-quoted value carries.

    Only the recognized set is consumed. An unrecognized escape keeps its
    backslash rather than dropping it, so a Windows path written
    ``"C:\\Users\\me"`` survives instead of becoming ``C:Usersme``.
    """
    out: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            following = value[index + 1]
            if following in _DOUBLE_QUOTE_ESCAPES:
                out.append(_DOUBLE_QUOTE_ESCAPES[following])
                index += 2
                continue
        out.append(char)
        index += 1
    return "".join(out)


def _references(value: str) -> set[str]:
    """Every name ``value`` interpolates, including inside a default.

    The grammar comes from :mod:`compose_lint.rules._interpolation` so the two
    readers of ``${...}`` cannot drift; only the question differs. That module
    asks what a document ships with no ``.env``; this one asks which names a
    ``.env`` entry depends on.
    """
    found: set[str] = set()
    index = 0
    while index < len(value):
        if value[index] != "$" or index + 1 >= len(value):
            index += 1
            continue
        following = value[index + 1]
        if following == "$":  # escaped literal dollar, not a reference
            index += 2
            continue
        if following == "{":
            close = _matching_brace(value, index + 1)
            if close is None:
                index += 1
                continue
            interior = value[index + 2 : close]
            name = re.match(r"[A-Za-z_][A-Za-z0-9_]*", interior)
            if name is not None:
                found.add(name.group())
            default = _default_of(interior)
            if default is not None:
                found |= _references(default)
            index = close + 1
            continue
        name = re.match(r"[A-Za-z_][A-Za-z0-9_]*", value[index + 1 :])
        if name is not None:
            found.add(name.group())
            index += 1 + len(name.group())
            continue
        index += 1
    return found


def _closure(entries: list[_Entry], wanted: Iterable[str] | None) -> set[str] | None:
    """Grow ``wanted`` until it contains everything needed to resolve it.

    ``None`` (meaning "all keys") is passed straight through — there is nothing
    to close over when nothing is excluded.
    """
    if wanted is None:
        return None
    by_key = {entry.key: entry for entry in entries}
    needed = set(wanted)
    pending = list(needed)
    while pending:
        entry = by_key.get(pending.pop())
        if entry is None or not entry.expands:
            continue
        for name in _references(entry.raw):
            if name not in needed:
                needed.add(name)
                pending.append(name)
    return needed


def _resolve(
    entries: list[_Entry],
    needed: set[str] | None,
    *,
    initial: Mapping[str, str] | None = None,
    bare_is_empty: bool = True,
) -> tuple[dict[str, str], set[str]]:
    """Expand entries in file order, which is the order Compose expands them.

    Order is load-bearing, not incidental: a reference to a key defined *later*
    resolves to empty in Compose (verified), so resolution is a single forward
    pass rather than a fixpoint. Here such a reference leaves the value
    unresolved instead of empty — the divergence in the module docstring — which
    keeps a value the tool cannot honestly build out of the rules' hands.

    A later duplicate key overwrites an earlier one, and an entry that fails to
    resolve removes any earlier successful binding for that key, so nothing
    downstream can read a stale value for a name the file went on to redefine.
    """
    values: dict[str, str] = dict(initial or {})
    unresolved: set[str] = set()
    for entry in entries:
        if entry.bare and not bare_is_empty:
            # An `env_file:` bare key is a process-environment lookup and
            # nothing else, so there is no file value to ship. Left unresolved
            # rather than guessed at, for the reason in divergence 1.
            unresolved.add(entry.key)
            values.pop(entry.key, None)
            continue
        resolved = entry.raw if not entry.expands else _expand(entry.raw, values)
        if resolved is None:
            unresolved.add(entry.key)
            values.pop(entry.key, None)
            continue
        unresolved.discard(entry.key)
        values[entry.key] = resolved
    if needed is not None:
        values = {key: value for key, value in values.items() if key in needed}
        unresolved &= needed
    return values, unresolved


def _expand(value: str, defined: Mapping[str, str]) -> str | None:
    """Substitute references against ``defined``, or ``None`` if any is unknown.

    ``None`` rather than an empty string is the whole of divergence 1: Compose
    would fall back to the process environment and then to empty, and both of
    those answers describe the machine running the lint rather than the project
    being linted.
    """
    out: list[str] = []
    produced = 0
    index = 0
    while index < len(value):
        if produced > MAX_SUBSTITUTED_LEN:
            return None
        char = value[index]
        if char != "$" or index + 1 >= len(value):
            out.append(char)
            produced += 1
            index += 1
            continue
        following = value[index + 1]
        if following == "$":
            # `$$` is the escape, and the value it produces carries a single
            # literal dollar: `K=a$$b` ships `a$b`, and `K=a$$A` ships `a$A`
            # with `A` deliberately not expanded. Verified by decoding
            # `docker compose config`, which re-escapes a literal dollar on the
            # way out (it prints `a$$b`) so its own output round-trips.
            out.append("$")
            produced += 1
            index += 2
            continue
        if following == "{":
            close = _matching_brace(value, index + 1)
            if close is None:
                out.append(char)
                produced += 1
                index += 1
                continue
            substituted = _substitute(value[index + 2 : close], defined)
            if substituted is None:
                return None
            out.append(substituted)
            produced += len(substituted)
            index = close + 1
            continue
        name = re.match(r"[A-Za-z_][A-Za-z0-9_]*", value[index + 1 :])
        if name is None:
            out.append(char)
            produced += 1
            index += 1
            continue
        if name.group() not in defined:
            return None
        out.append(defined[name.group()])
        produced += len(defined[name.group()])
        index += 1 + len(name.group())
    if produced > MAX_SUBSTITUTED_LEN:
        return None
    return "".join(out)


def _substitute(interior: str, defined: Mapping[str, str]) -> str | None:
    """Resolve one ``${...}`` interior against ``defined``."""
    name = re.match(r"[A-Za-z_][A-Za-z0-9_]*", interior)
    if name is None:
        return None
    key = name.group()
    if key in defined:
        return defined[key]
    default = _default_of(interior)
    if default is None:
        return None  # nothing to fall back to but the host's environment
    return _expand(default, defined)


def read_env_file(
    path: Path,
    *,
    defined: Mapping[str, str] | None = None,
    raw: bool = False,
) -> EnvFile | None:
    """Read one ``env_file:`` target, or ``None`` if it cannot be read.

    ``None`` covers absent, unreadable, over-cap and undecodable alike, because
    the caller's next move is the same for all four: say the file was not read
    and grade nothing from it. Compose distinguishes them — an absent
    ``required`` target aborts the run — but that distinction is about whether
    the project deploys, which the caller answers by testing the path, not by
    reading it.

    ``defined`` seeds the names this file's values may reference: the sibling
    ``.env`` and every earlier ``env_file:`` on the same service, which is the
    scope Compose resolves against (verified: ``P=${BASE}/p`` in the second file
    picks up ``BASE`` from the first). Seeded names are *not* returned — only
    keys this file writes are, because only those are keys it contributes to the
    container.

    Unlike :func:`read_env`, nothing is filtered by wantedness. Every key in an
    ``env_file:`` is deployed into a named service's process environment, so
    every key is one a rule may grade (ADR-027 §4).
    """
    try:
        text = read_text_bounded(path, max_bytes=MAX_ENV_BYTES)
    except (FileNotFoundError, UnsafeFileError, UnicodeDecodeError, OSError):
        return None
    return parse_env_file(text, defined=defined, raw=raw)


def parse_env_file(
    text: str,
    *,
    defined: Mapping[str, str] | None = None,
    raw: bool = False,
) -> EnvFile:
    """Parse one ``env_file:`` target's text.

    ``raw`` is the ``format: raw`` spelling, which is a different grammar rather
    than a relaxed one — see :func:`_scan`. In both grammars a bare ``KEY`` is
    Compose's process-environment lookup and is reported unresolved, which is
    where this reader diverges from :func:`parse_env`: a ``.env`` ships that key
    empty.
    """
    entries, skipped = _scan(text, raw=raw)
    own = {entry.key for entry in entries}
    values, unresolved = _resolve(entries, own, initial=defined, bare_is_empty=False)
    # Last definition wins, so the line recorded is the one whose value shipped.
    lines = {entry.key: entry.line for entry in entries if entry.key in values}
    return EnvFile(
        values=values,
        unresolved=frozenset(unresolved),
        skipped_lines=tuple(skipped),
        lines=lines,
    )


def env_file_references(text: str, *, raw: bool = False) -> set[str]:
    """Every name an ``env_file:``'s values interpolate.

    Exists so that the sibling ``.env`` can be read for exactly the names an
    ``env_file:`` chains to, instead of being read in full. Compose resolves an
    ``env_file:`` value against the ``.env`` (verified: ``K=${FROMDOTENV}-tail``
    ships the ``.env``'s value), so those names have to be in scope — but
    ADR-026 §5 keeps the ``.env`` read narrowed to what a run needs, and reading
    it wholesale to serve this would quietly retire that guarantee. Scanning the
    env file first costs one extra pass and keeps both promises intact.

    Nothing is resolved here, so no value is assembled.
    """
    entries, _ = _scan(text, raw=raw)
    found: set[str] = set()
    for entry in entries:
        if entry.expands:
            found |= _references(entry.raw)
    return found
