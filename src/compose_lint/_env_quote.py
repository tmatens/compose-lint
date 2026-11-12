"""Quote ``.env`` values back to their ``${NAME}`` in what the run prints.

A sibling ``.env`` is read so a reference is graded as Compose would deploy it,
but the values in it are often secrets a CI job wrote there, and the report is
read by whoever opened the pull request. A finding quotes the reference instead
of the value (:func:`compose_lint.engine.run_rules`, scoped per service). This
module does the same for everything else the run says: coverage gaps, notes,
warnings and errors, on stderr and in the JSON and SARIF documents.

Those messages are built in many places, from text that has already been
substituted (an ``include:`` path, an ``env_file:`` target, an ``extends:``
service name), so quoting at each place is opt-in and was missed. Instead the
parser records every value it substitutes here, and the sinks quote on the way
out: :func:`compose_lint._output.emit` and the JSON and SARIF diagnostic
builders. The record is process-wide because a run is one process and the
sinks have no handle on the document that produced the message.

The whole run's values are used, not one document's or one service's. A
diagnostic is compose-lint's own sentence around a reference, so a value
written literally elsewhere is not at risk the way a finding about another
service would be, and the floor below keeps configuration tokens out.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

# The shortest value replaced by its reference. A secret is often glued to the
# text around it (`image: "app${TOKEN}"`), so a value is matched anywhere, not
# as a whole word, and that is what makes a floor necessary: short values are
# configuration tokens (`true`, `host`, `latest`, `1000`) that the rules' own
# guidance also writes, and replacing them there turned `no-new-privileges:true`
# into `no-new-privileges:${PRIV}`. A value a CI job writes as a secret is
# longer than this.
QUOTED_FROM = 8

# What a value is split on before part of it is quoted: image references,
# ports, mounts, `key=value` options, lists. A message can quote a piece of a
# value as easily as the whole of it.
SEPARATORS = re.compile(r"[:/@=,;\s]+")

_names: dict[str, str] = {}
_pattern: re.Pattern[str] | None = None


def quotable(name: str, value: str) -> dict[str, str]:
    """``value`` and each separated part of it long enough to quote, to ``name``."""
    pieces: dict[str, str] = {}
    for piece in (value, *SEPARATORS.split(value)):
        if len(piece) >= QUOTED_FROM:
            pieces.setdefault(piece, name)
    return pieces


def remember(env_values: Mapping[str, Mapping[str, str]]) -> None:
    """Add what a ``.env`` substituted (``Loaded.env_values``' shape)."""
    global _pattern
    added = False
    for used in env_values.values():
        for name, value in used.items():
            for piece, piece_name in quotable(name, value).items():
                if piece not in _names:
                    _names[piece] = piece_name
                    added = True
    if added:
        alternatives = "|".join(
            re.escape(value) for value in sorted(_names, key=len, reverse=True)
        )
        _pattern = re.compile(alternatives)


def quote(text: str) -> str:
    """``text`` with every remembered value replaced by its ``${NAME}``."""
    if _pattern is None:
        return text
    return _pattern.sub(lambda m: "${" + _names[m.group(0)] + "}", text)


def forget() -> None:
    """Drop every remembered value. For tests and for a library caller."""
    global _pattern
    _names.clear()
    _pattern = None
