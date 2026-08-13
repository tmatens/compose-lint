"""Read a YAML *scalar* leaf as text, refusing containers.

``str(value)`` on a leaf looks harmless until the leaf is a list. YAML aliases
let a document reference the same node many times, so ``l1: [*l0, *l0]``
repeated 22 times is a few hundred bytes on disk and a DAG of 22 nodes in
memory — but ``str()`` serializes it as a *tree*, materializing 2^22 elements
in one call. The file parses in milliseconds; the rule layer then burns CPU and
memory on a document that produces no findings and exits 0, so nothing in the
output signals what happened.

The fix is not a size cap on the result — by the time there is a result the
allocation has already happened. It is to notice that a list is not a value any
of these fields can hold. ``cap_add: [[a, b]]``, ``user: {a: b}`` and
``network_mode: [x]`` are not configurations Docker accepts; a rule comparing
them against a set of dangerous strings has nothing to compare. Returning
``None`` lets each caller skip the entry, which is what it would have done with
the giant string anyway.
"""

from __future__ import annotations

from typing import Any

# The YAML scalar types PyYAML's SafeLoader produces. `datetime` and `date` are
# included because a bare `2024-01-01` resolves to one, and a rule reading it as
# text is well-defined; a list or dict is not.
_SCALAR_TYPES = (str, int, float, bool, bytes)


def as_scalar_text(value: Any) -> str | None:
    """Return ``value`` as text if it is a scalar, else ``None``.

    ``None`` (a bare YAML ``null``) is itself a scalar and renders as ``"None"``,
    preserving what ``str()`` did for the fields that check for it.
    """
    if value is None or isinstance(value, _SCALAR_TYPES):
        return str(value)
    if isinstance(value, (list, dict, set, tuple)):
        return None
    # An unexpected type (a date, say) is still a leaf, not a container.
    return str(value)
