"""A rule's doc page must list exactly the names its code matches on.

`docs/rules/CL-0020.md` spells its key patterns and exemptions out as
backticked names in prose. That page is what someone opens to find out why
CL-0020 flagged — or spared — their key, so a name the page lists that the
code does not match sends them hunting for a typo in their own file, and a
name the code matches that the page omits leaves them with no explanation at
all. #685 shipped the first kind three ways in one PR — an exemption the
tuples did not have, and three suffix-anchored entries listed without the
underscore that does the anchoring — and it was caught by a reviewer
re-reading the tuples against the page by hand, twice. Nothing else could
have caught it: CONTRIBUTING asks for the doc edit, and no gate checked it.

Same idea as `tests/test_rule_surfaces.py`, one level down: that test holds
the *set of rules* together across its surfaces; this one holds a *single
rule's* constants together with the page describing them. Each surface is
anchored to the line that carries it, so a failure names the list and the
names, not the file.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from compose_lint.rules import CL0020_credential_env_keys as cl0020

DOC = Path(__file__).parent.parent / "docs" / "rules" / "CL-0020.md"

# A backticked name as the code would spell it: upper-case, possibly anchored
# with a leading or trailing underscore. Excludes the illustrative
# `KEY: value` pairs and bare numbers that share the same lines.
_NAME = re.compile(r"`(_?[A-Z][A-Z0-9_]*)`")
# The boolean-flag values are the one lower-case list.
_VALUE = re.compile(r"`([a-z0-9]+)`")


def _line(anchor: str) -> str:
    lines = DOC.read_text(encoding="utf-8").splitlines()
    matches = [ln for ln in lines if anchor in ln]
    assert len(matches) == 1, (
        f"expected one line containing {anchor!r}, found {len(matches)}"
    )
    return matches[0]


def _table_cell(anchor: str) -> str:
    """The Pattern cell of a `| type | patterns | notes |` row.

    The Notes cell can legitimately quote a name the code does *not* match —
    the suffix row explains why raw `PASS` is excluded — so only the cell
    that claims to list patterns is read.
    """
    return _line(anchor).split("|")[2]


SURFACES: dict[str, tuple[str, re.Pattern[str], frozenset[str]]] = {
    "substring patterns": (
        _table_cell("| substring |"),
        _NAME,
        frozenset(cl0020._SUBSTRING_PATTERNS),
    ),
    "suffix patterns": (
        _table_cell("| suffix "),
        _NAME,
        frozenset(cl0020._SUFFIX_PATTERNS),
    ),
    "file-suffix exemption": (
        _line("- Keys ending in"),
        _NAME,
        frozenset({cl0020._FILE_SUFFIX}),
    ),
    "flag-key exemption": (
        _line("- Keys containing"),
        _NAME,
        frozenset(cl0020._FLAG_KEY_FRAGMENTS),
    ),
    "flag-value exemption": (
        _line("- Values that are exactly"),
        _VALUE,
        frozenset(cl0020._FLAG_VALUES),
    ),
    "quantity-knob exemption": (
        _line("- Keys that name a **quantity about**"),
        _NAME,
        frozenset(cl0020._QUANTITY_KEY_FRAGMENTS)
        | frozenset(cl0020._QUANTITY_KEY_SUFFIXES),
    ),
}


@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_doc_lists_exactly_what_the_code_matches(surface: str) -> None:
    line, pattern, in_code = SURFACES[surface]
    in_doc = frozenset(pattern.findall(line))
    promised = sorted(in_doc - in_code)
    undocumented = sorted(in_code - in_doc)
    assert not promised, (
        f"CL-0020.md lists {promised} under '{surface}' but the code does not "
        "match them — a documented pattern that does not exist. Check the "
        "spelling, including a leading underscore on suffix-anchored names."
    )
    assert not undocumented, (
        f"the code matches {undocumented} under '{surface}' but CL-0020.md does "
        "not list them — add them to that line so the page explains every key "
        "the rule treats this way."
    )
