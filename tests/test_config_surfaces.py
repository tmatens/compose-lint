"""Every config diagnostic must be documented where users look for it.

`docs/configuration.md`'s Validation section reads as an exhaustive list of
what a bad `.compose-lint.yml` gets told, and users treat it that way — it is
the page that answers "why did my suppression not take effect?". Nothing held
the code and that list together, so the list could fall behind silently, and
did: #826 added the inert-`reason:` warning and the section kept describing
four diagnostics. That was not a contributor oversight. CONTRIBUTING points at
`docs/rules/CL-XXXX.md` for rule changes and `README.md` for CLI changes, and a
config diagnostic is neither, so nothing in the repo asked for the edit.

The pairing is deliberately dumb: a `# diag: <slug>` comment above each
`_warn` call in `config.py`, a `<!-- diag: <slug> -->` marker on the bullet
that documents it, and this test asserting the two sets match. A new
diagnostic then fails CI naming the missing slug rather than waiting for a
reader to notice the omission. Same reasoning as
`tests/test_rule_surfaces.py`: a list maintained by hand goes stale exactly
when nobody is looking at it.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).parent.parent
CONFIG_SRC = (REPO / "src" / "compose_lint" / "config.py").read_text(encoding="utf-8")
CONFIG_DOC = (REPO / "docs" / "configuration.md").read_text(encoding="utf-8")

# A marker only counts when it sits directly above the `_warn` it labels, so a
# stray comment elsewhere in the module cannot satisfy the pairing.
_MARKED_CALL = re.compile(r"^[ \t]*# diag: ([a-z0-9-]+)\n[ \t]*_warn\(", re.M)
_WARN_CALL = re.compile(r"(?<!def )\b_warn\(")
_DOC_MARKER = re.compile(r"<!-- diag: ([a-z0-9-]+) -->")


def test_every_warn_call_site_is_labelled() -> None:
    """A `_warn` without a marker would pass the set check below by absence."""
    calls = len(_WARN_CALL.findall(CONFIG_SRC))
    marked = _MARKED_CALL.findall(CONFIG_SRC)
    assert len(marked) == calls, (
        f"{calls} _warn call(s) in config.py, {len(marked)} carrying a "
        "'# diag: <slug>' comment on the line above — label the new one and "
        "document it in docs/configuration.md."
    )
    assert len(set(marked)) == len(marked), f"duplicate diag slugs: {sorted(marked)}"


def test_every_diagnostic_is_documented() -> None:
    in_code = set(_MARKED_CALL.findall(CONFIG_SRC))
    in_docs = set(_DOC_MARKER.findall(CONFIG_DOC))
    undocumented = sorted(in_code - in_docs)
    orphaned = sorted(in_docs - in_code)
    assert not undocumented, (
        f"{undocumented} warn(s) but docs/configuration.md does not document "
        "them — add a bullet to the Validation section ending in "
        "'<!-- diag: <slug> -->'."
    )
    assert not orphaned, (
        f"docs/configuration.md documents {orphaned}, which config.py no "
        "longer emits — drop the bullet or the marker."
    )
