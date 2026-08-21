"""Shared classification of Compose variable substitution.

:func:`substitute_defaults` is applied by the parser to every string leaf in the
document (``parser._substitute_interpolation_defaults``), so a rule compares
against the value Compose actually ships rather than the ``${VAR:-...}`` source
text. Rules therefore do **not** re-implement interpolation handling; the one
question left for them is whether a value that *survived* normalization ships
anything literal at all, which :func:`ships_no_literal` answers.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from compose_lint._limits import MAX_SCAN_LEN

if TYPE_CHECKING:
    from collections.abc import Mapping

# Upper bound on a scalar these regexes will scan. Both the pattern below and
# the two in `substitute_defaults` are quadratic on pathological input (measured
# 4x per doubling: 80 KB -> 0.49 s, 160 KB -> 1.94 s), and the parser now runs
# substitution over *every* string in the document rather than bind sources
# alone. A Compose scalar this long carries no classification signal worth that
# cost, so beyond the cap the conservative answer is returned without scanning.
_MAX_SCAN_LEN = MAX_SCAN_LEN

# An active variable substitution ("${VAR}", "${VAR:-default}", "$VAR").
_VAR_REF_RE = re.compile(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*")

# The head of a "${...}" interior: the name, and the operator that follows it.
# ":-" and "-" introduce a default (Compose distinguishes them -- ":-"
# substitutes when unset *or empty*, "-" only when unset -- but both yield the
# same default for a file carrying no .env, which is the case being resolved).
# ":?"/"?" and ":+"/"+" do not: they carry an error message or an alternate,
# so a reference spelled with one has no default to resolve to.
_REF_HEAD_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(:?[-?+])?")

_DEFAULT_OPERATORS = frozenset({":-", "-"})

# How deep a chain of nested defaults will be resolved. Resolution recurses
# into each default, so without a bound a scalar of `${A:-` repeated ~1,200
# times -- 7 KB, under `MAX_SCAN_LEN` -- exhausts the interpreter stack, and
# the parser turns that RecursionError into a usage error. A file that lints
# clean today would exit 2 instead, which is the denial of service
# `_limits.MAX_SCAN_LEN` exists to close, arriving by a different route. Real
# files nest two or three deep; the deepest in a 5,417-file corpus is three.
_MAX_NESTING = 32

# A reference with no default: "${VAR}", "$VAR", "${VAR:?err}". Nothing to
# resolve to, so a value containing one is left exactly as written.
_VAR_NO_DEFAULT_RE = re.compile(
    r"\$\{[A-Za-z_][A-Za-z0-9_]*(:?[?+][^}]*)?\}|\$[A-Za-z_][A-Za-z0-9_]*"
)


def ships_no_literal(value: str) -> bool:
    """Whether Compose ships ``value`` as empty, leaving nothing to classify.

    This is the exemption a credential rule should grant, and it is stated as
    what Compose *does* rather than as a shape the text happens to have. An
    unset reference with no default substitutes to nothing — ``${PW}`` ships
    ``POSTGRES_PASSWORD: ""`` (verified with ``docker compose config``) — so a
    value made only of such references carries no secret.

    Asking instead whether a value merely *contains* a reference exempted
    ``hunter2$X``, which ships the literal ``hunter2``: one appended character
    silenced the rule. Asking whether it is *exactly* one reference is the
    opposite error — it flagged ``- SECRET_KEY="${PLANKA_SECRET_KEY}"``, where
    the quotes are literal characters of a list-form entry and the secret is
    properly externalized (8 such values across the corpus). Resolving to empty
    is the test that gets both right.

    ``$$`` is Compose's literal-dollar escape, consumed before interpolation,
    so stripping the escapes first leaves exactly the dollars Compose treats as
    syntax. A *defaulted* reference is deliberately not removed: its default is
    the literal the file ships.
    """
    if len(value) > _MAX_SCAN_LEN:
        return False  # too long to classify; not exempt
    text = value.replace("$$", "")
    # A list-form entry ("- KEY=value") is one plain scalar, so quotes around
    # the value are literal characters rather than YAML syntax. They carry no
    # secret, so judge what they wrap.
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1]
    return _VAR_NO_DEFAULT_RE.sub("", text) == ""


def _matching_brace(value: str, start: int) -> int | None:
    """Index of the ``}`` closing the ``{`` at ``start``, or ``None``.

    Braces are counted whether or not a ``$`` precedes them, because a default
    may contain a literal one: Compose resolves ``${CONF:-{"a":1}}`` to
    ``{"a":1}``, which only balanced counting reproduces.
    """
    depth = 0
    for i in range(start, len(value)):
        char = value[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def _resolve_defaults(
    value: str, depth: int = 0, env: Mapping[str, str] | None = None
) -> str | None:
    """Rewrite each reference to its value: ``env`` first, then its default.

    A single regex pass cannot do this. With the default written ``[^}]*`` it
    stops at the *first* ``}``, which for a nested reference is the inner one:
    ``${DB_URL:-postgres://u:${PW:-s3cret}@db/x}`` resolved to
    ``postgres://u:${PW:-s3cret@db/x}`` — a string Compose never ships, with
    the userinfo boundary moved and the closing brace relocated past the host.
    98 corpus values across 34 files are shaped this way, bind mount sources
    (``${GOPATH:-${HOME}/go}/pkg/mod/cache``) among them, so the corruption
    reached the host-path rules as well as the credential ones (issue #561).
    Compose's own resolution was captured with ``docker compose config`` on a
    file carrying no ``.env``:

    ====================================  ==========================
    written                               shipped
    ====================================  ==========================
    ``${A:-front-${B:-back}-tail}``       ``front-back-tail``
    ``${CONF:-{"a":1}}``                  ``{"a":1}``
    ====================================  ==========================

    A reference with no default is copied through **as written** rather than
    resolved or dropped, leaving :func:`substitute_defaults` to make the
    not-knowable call on the whole value exactly as before. ``None`` means the
    value nests deeper than ``_MAX_NESTING`` and is treated as unknowable for
    the same reason -- returning the partially-resolved text would claim
    Compose ships something it does not.
    """
    if depth > _MAX_NESTING:
        return None
    lookup: Mapping[str, str] = env or {}
    out: list[str] = []
    i = 0
    end = len(value)
    while i < end:
        char = value[i]
        if char == "$" and i + 1 < end:
            following = value[i + 1]
            if following == "$":  # escaped literal dollar, not a reference
                out.append("$$")
                i += 2
                continue
            if following == "{":
                close = _matching_brace(value, i + 1)
                if close is not None:
                    interior = value[i + 2 : close]
                    supplied = _supplied(interior, lookup)
                    if supplied is not None:
                        out.append(supplied)
                        i = close + 1
                        continue
                    default = _default_of(interior)
                    if default is not None:
                        resolved = _resolve_defaults(default, depth + 1, env)
                        if resolved is None:
                            return None
                        out.append(resolved)
                        i = close + 1
                        continue
                    out.append(value[i : close + 1])  # no default; as written
                    i = close + 1
                    continue
            name = _BARE_NAME_RE.match(value, i + 1)
            if name is not None and name.group() in lookup:
                out.append(lookup[name.group()])
                i = name.end()
                continue
        out.append(char)
        i += 1
    return "".join(out)


# The name in a bare `$VAR` reference. Only consulted when a `.env` supplies
# that name: without one the value is left as written, exactly as before.
_BARE_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def reference_names(value: str) -> set[str]:
    """Every variable name ``value`` interpolates, defaults included.

    The wanted-set filter (ADR-026 §5) needs this before anything is resolved:
    only the names a document could consume are read out of a ``.env``, and
    everything else is discarded rather than parsed into the run.
    """
    if len(value) > _MAX_SCAN_LEN:
        return set()
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
            head = _REF_HEAD_RE.match(interior)
            if head is not None:
                found.add(head.group(1))
            default = _default_of(interior)
            if default is not None:
                found |= reference_names(default)
            index = close + 1
            continue
        name = _BARE_NAME_RE.match(value, index + 1)
        if name is None:
            index += 1
            continue
        found.add(name.group())
        index = name.end()
    return found


def _supplied(interior: str, env: Mapping[str, str]) -> str | None:
    """What ``env`` supplies for a ``${...}`` interior, or ``None``.

    A supplied value beats a written default, which is Compose's precedence --
    the default applies only when the variable is unset. Operators that carry
    no default (``:?``/``?``, ``:+``/``+``) are left to the caller, because
    what they ship is not the variable's value.
    """
    head = _REF_HEAD_RE.match(interior)
    if head is None:
        return None
    operator = head.group(2)
    if operator is not None and operator not in _DEFAULT_OPERATORS:
        return None
    return env.get(head.group(1))


def _default_of(interior: str) -> str | None:
    """The default an interpolation interior carries, or ``None`` if it has none."""
    head = _REF_HEAD_RE.match(interior)
    if head is None or head.group(2) not in _DEFAULT_OPERATORS:
        return None
    return interior[head.end() :]


def substitute_defaults(value: str, env: Mapping[str, str] | None = None) -> str | None:
    """Resolve ``${VAR}`` against ``env`` and ``${VAR:-default}`` to its default.

    ``env`` is what a sibling ``.env`` supplies (ADR-026). It wins over a
    written default, because that is Compose's own precedence: the default
    applies only when the variable is unset. Without it the function answers
    the narrower question it always did -- what the document ships on its own.

    With no ``.env`` and no exported variable, Compose substitutes the default,
    so the default *is* the configuration the file ships: it is what a fresh
    clone, a reviewer and a CI gate all get. Leaving it unresolved hid real
    findings -- ``${DOCKER_SOCKET_PATH:-/var/run/docker.sock}`` mounts the live
    control socket and was reported clean, 13 times over the corpus.

    Returns ``None`` when any reference in the value has no default, because
    then the host path genuinely is not knowable from this file and guessing
    one would invent a finding. Deliberately narrow: it answers "what does this
    file do on its own", not "what will it do in your deployment", and a
    deployment that sets the variable is the case suppressions exist for.
    """
    if len(value) > _MAX_SCAN_LEN:
        # Conservative: report the value as unknowable rather than spend
        # quadratic time proving it. Callers leave such a scalar as written,
        # which is exactly the behavior before substitution was document-wide.
        return None
    escaped = value.replace("$$", "")
    if not _VAR_REF_RE.search(escaped):
        return value  # nothing to substitute
    resolved = _resolve_defaults(value, env=env)
    if resolved is None:
        return None  # nested deeper than we resolve -- not knowable
    if _VAR_NO_DEFAULT_RE.search(resolved.replace("$$", "")):
        return None  # a reference without a default remains -- not knowable
    return resolved
