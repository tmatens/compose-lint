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
