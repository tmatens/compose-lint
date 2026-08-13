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

from compose_lint._limits import MAX_SCAN_LEN

# Upper bound on a scalar these regexes will scan. Both the pattern below and
# the two in `substitute_defaults` are quadratic on pathological input (measured
# 4x per doubling: 80 KB -> 0.49 s, 160 KB -> 1.94 s), and the parser now runs
# substitution over *every* string in the document rather than bind sources
# alone. A Compose scalar this long carries no classification signal worth that
# cost, so beyond the cap the conservative answer is returned without scanning.
_MAX_SCAN_LEN = MAX_SCAN_LEN

# An active variable substitution ("${VAR}", "${VAR:-default}", "$VAR").
_VAR_REF_RE = re.compile(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*")

# "${VAR:-default}" and "${VAR-default}". Compose distinguishes them -- ":-"
# substitutes when unset *or empty*, "-" only when unset -- but both yield the
# same default for a file carrying no .env, which is the case being resolved.
# Non-greedy up to the first "}", so a trailing literal survives:
# "${DIR:-/srv}/data" -> "/srv/data".
_VAR_DEFAULT_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*):?-([^}]*)\}")

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


def substitute_defaults(value: str) -> str | None:
    """Resolve ``${VAR:-default}`` to its default, or ``None`` if unresolvable.

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
    resolved = _VAR_DEFAULT_RE.sub(lambda m: m.group(2), value)
    if _VAR_NO_DEFAULT_RE.search(resolved.replace("$$", "")):
        return None  # a reference without a default remains -- not knowable
    return resolved
