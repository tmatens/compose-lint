"""Shared classification of Compose variable substitution in env values."""

from __future__ import annotations

import re

# An active variable substitution ("${VAR}", "${VAR:-default}", "$VAR").
_VAR_REF_RE = re.compile(r"\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*")


def contains_var_ref(value: str) -> bool:
    """Return True if ``value`` contains a ``$VAR``/``${VAR}`` substitution.

    Compose writes a literal dollar as ``$$`` and consumes those escapes
    left-to-right before interpolation, so ``pa$$w0rd`` is a literal
    credential, not a reference to ``$w0rd`` (issue #502). ``str.replace``
    removes non-overlapping ``$$`` pairs in the same left-to-right order,
    so exactly the dollars Compose would treat as syntax remain to be
    tested against the reference pattern.
    """
    return _VAR_REF_RE.search(value.replace("$$", "")) is not None


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
    escaped = value.replace("$$", "")
    if not _VAR_REF_RE.search(escaped):
        return value  # nothing to substitute
    resolved = _VAR_DEFAULT_RE.sub(lambda m: m.group(2), value)
    if _VAR_NO_DEFAULT_RE.search(resolved.replace("$$", "")):
        return None  # a reference without a default remains -- not knowable
    return resolved
