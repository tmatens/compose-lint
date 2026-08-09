"""Boolean coercion matching Docker's compose-file compatibility.

Compose boolean-typed fields accept the YAML 1.1 boolean spellings and their
quoted string forms; ``docker compose config`` coerces ``privileged: "true"``
and ``privileged: yes`` alike to a real boolean. The parser keeps *unquoted*
spellings as bools, but a quoted ``"true"``/``"yes"`` reaches a rule as a
string, so a rule that tests ``is True`` misreads it. Use ``as_bool`` for every
boolean-typed field so string and native forms are treated identically.
"""

from __future__ import annotations

from typing import Any

_TRUE = frozenset({"true", "yes", "on"})
_FALSE = frozenset({"false", "no", "off"})


def as_bool(value: Any) -> bool | None:
    """Return True/False for a bool or a YAML boolean spelling, else None."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in _TRUE:
            return True
        if low in _FALSE:
            return False
    return None
