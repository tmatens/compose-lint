"""Every place the rule set is listed must list the same rules.

A rule id appears in six places: the registry, its own doc page, the README
table, the docs-site index, the mkdocs nav, and `docs/severity.md`'s assignment
table. Adding or removing a rule means touching all six, and nothing forces
that — a missed one is invisible until a user follows a dead link or wonders
why a rule they hit is undocumented.

`severity.md` and the ATT&CK map already have their own coverage tests; this
covers the remaining surfaces, and does it as one parameterised check so a
failure names the surface rather than making someone diff six lists by hand.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from compose_lint.rules import get_registered_rules

REPO = Path(__file__).parent.parent

REGISTERED = {cls().metadata.id for cls in get_registered_rules()}

# Ids that were used and retired. They must NOT reappear: reusing one silently
# rewrites the meaning of a suppression someone already wrote (ADR-005), and
# pre-1.0 reclamation ended with CL-0023.
FALLOW = {"CL-0012", "CL-0015", "CL-0023"}


def _listed(path: str, pattern: str) -> set[str]:
    return set(re.findall(pattern, (REPO / path).read_text(encoding="utf-8"), re.M))


SURFACES = {
    "README rule table": _listed("README.md", r"^\| \[(CL-\d{4})\]"),
    "docs/index.md rule table": _listed("docs/index.md", r"^\| \[(CL-\d{4})\]"),
    "mkdocs nav": _listed("mkdocs.yml", r"rules/(CL-\d{4})\.md"),
    "docs/rules/ pages": {p.stem for p in (REPO / "docs" / "rules").glob("CL-*.md")},
}


@pytest.mark.parametrize("surface", sorted(SURFACES), ids=lambda s: s.split()[0])
def test_surface_lists_exactly_the_registered_rules(surface: str) -> None:
    listed = SURFACES[surface]
    missing = sorted(REGISTERED - listed)
    extra = sorted(listed - REGISTERED)
    assert not missing, f"{surface} is missing {missing}"
    assert not extra, (
        f"{surface} lists {extra}, which no longer exist. A dropped rule has to "
        "leave every surface, or it keeps sending readers to a rule that cannot "
        "fire."
    )


def test_retired_ids_are_not_reused() -> None:
    reused = FALLOW & REGISTERED
    assert not reused, (
        f"{sorted(reused)} were retired and must stay fallow — reusing an id "
        "silently changes what an existing suppression means (ADR-005)."
    )


@pytest.mark.parametrize("surface", sorted(SURFACES), ids=lambda s: s.split()[0])
def test_retired_ids_are_gone_from_every_surface(surface: str) -> None:
    lingering = sorted(FALLOW & SURFACES[surface])
    assert not lingering, f"{surface} still lists retired {lingering}"
