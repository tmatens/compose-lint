"""``docs/severity.md`` is the derivation of record — this test enforces it.

Before this test existed, seven of twenty-four assignment rows named a matrix
cell that does not produce the severity printed beside it. That was not seven
independent mistakes: with no sanctioned way to ship a number different from the
derived one, a contributor who disagreed with the derivation edited the
derivation, and the edit was invisible to review.

The four assertions below close that off. Every registered rule appears in the
table exactly once; every row's cell (after its qualifier or modifier) yields the
severity printed as ``Derived``; every ``Shipped`` value equals the rule's
``metadata.severity`` in code; and any row where the two differ carries an
override reason from the closed list **plus** a link. The fourth is what makes
back-solving structurally impossible rather than merely discouraged — a
disagreement with the derivation now has exactly one legal outlet, and it is a
reviewable one.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from compose_lint.models import Severity
from compose_lint.rules import get_registered_rules

SEVERITY_DOC = Path(__file__).parent.parent / "docs" / "severity.md"
RULE_DOCS = Path(__file__).parent.parent / "docs" / "rules"

# The closed list from ``docs/severity.md``. Extending it is an ADR-level
# decision, not a test edit — the point of the list is that "just override it"
# stays expensive.
OVERRIDE_REASONS = frozenset({"detection-precision", "pending-split", "pending-move"})

# Ordered low to high; qualifiers and modifiers step along this list.
TIERS: tuple[Severity, ...] = (
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)

# Qualifier/modifier column values and the number of tiers each shifts.
ADJUSTMENTS: dict[str, int] = {
    "—": 0,
    "read-only": -1,
    "availability-only": -1,
    "integrity-only": -1,
    "pre-foothold reach": +1,
}

NONE_CELL = "—"
RULE_ID_RE = re.compile(r"CL-\d{4}")
OVERRIDE_REASON_RE = re.compile(r"^`([a-z-]+)`")
MARKDOWN_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")

_SHIPPED: dict[str, Severity] = {
    cls().metadata.id: cls().metadata.severity for cls in get_registered_rules()
}


def _cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _table_after(heading: str) -> list[list[str]]:
    """Return the body rows of the first markdown table below ``heading``."""
    lines = SEVERITY_DOC.read_text(encoding="utf-8").splitlines()
    start = next((i for i, line in enumerate(lines) if line.strip() == heading), -1)
    assert start >= 0, f"{SEVERITY_DOC.name}: heading {heading!r} not found"
    rows: list[list[str]] = []
    in_table = False
    for line in lines[start + 1 :]:
        stripped = line.strip()
        if not stripped.startswith("|"):
            if in_table:
                break
            continue
        in_table = True
        cells = _cells(stripped)
        if all(set(cell) <= {"-", ":"} and cell for cell in cells):
            continue  # the ---|--- separator
        rows.append(cells)
    return rows


def _matrix() -> dict[tuple[str, str], Severity]:
    """Parse the 4x3 matrix into ``(precondition, impact) -> Severity``."""
    rows = _table_after("## Matrix")
    header, *body = rows
    impacts = header[1:]
    cell_map: dict[tuple[str, str], Severity] = {}
    for row in body:
        precondition = row[0].strip("*")
        for impact, severity in zip(impacts, row[1:], strict=True):
            cell_map[(precondition, impact)] = Severity(severity.lower())
    return cell_map


def _assignments() -> list[dict[str, str]]:
    rows = _table_after("## Current rule assignments")
    header, *body = rows
    return [dict(zip(header, row, strict=True)) for row in body]


MATRIX = _matrix()
ASSIGNMENTS = _assignments()
ASSIGNMENT_IDS = [
    match.group(0)
    for row in ASSIGNMENTS
    if (match := RULE_ID_RE.search(row["Rule"])) is not None
]


def test_matrix_is_complete() -> None:
    """All twelve cells parse, so a typo cannot silently drop one."""
    preconditions = {"Direct", "Technique", "Second flaw", "Removes a mitigation"}
    impacts = {"Host", "Cross-container", "Single container"}
    assert set(MATRIX) == {(p, i) for p in preconditions for i in impacts}


def test_every_rule_appears_exactly_once() -> None:
    """The table is the derivation of record, so it must cover the registry."""
    assert len(ASSIGNMENT_IDS) == len(ASSIGNMENTS), (
        "an assignment row has no CL-NNNN id in its Rule cell"
    )
    duplicates = {i for i in ASSIGNMENT_IDS if ASSIGNMENT_IDS.count(i) > 1}
    assert not duplicates, f"rules listed more than once: {sorted(duplicates)}"
    assert set(ASSIGNMENT_IDS) == set(_SHIPPED), (
        "docs/severity.md and the rule registry disagree: "
        f"documented-only={sorted(set(ASSIGNMENT_IDS) - set(_SHIPPED))}, "
        f"registered-only={sorted(set(_SHIPPED) - set(ASSIGNMENT_IDS))}"
    )


def test_assignments_are_sorted_by_rule_id() -> None:
    """Sorted by id, not by severity — six rows used to read as missing."""
    assert sorted(ASSIGNMENT_IDS) == ASSIGNMENT_IDS


@pytest.mark.parametrize("row", ASSIGNMENTS, ids=ASSIGNMENT_IDS)
def test_cell_yields_the_printed_derived_severity(row: dict[str, str]) -> None:
    """The derivation is arithmetic, not assertion: recompute it from the cell."""
    rule_id = RULE_ID_RE.search(row["Rule"])
    assert rule_id is not None
    cell = (row["Precondition"], row["Impact"])
    assert cell in MATRIX, f"{rule_id.group(0)}: {cell} is not a matrix cell"
    qualifier = row["Qualifier"]
    assert qualifier in ADJUSTMENTS, (
        f"{rule_id.group(0)}: unknown qualifier/modifier {qualifier!r}; "
        f"allowed: {sorted(ADJUSTMENTS)}"
    )
    index = TIERS.index(MATRIX[cell]) + ADJUSTMENTS[qualifier]
    expected = TIERS[min(max(index, 0), len(TIERS) - 1)]
    assert Severity(row["Derived"].lower()) == expected, (
        f"{rule_id.group(0)}: {cell[0]} × {cell[1]}"
        f"{'' if qualifier == NONE_CELL else f' + {qualifier}'} yields "
        f"{expected.value.upper()}, but the row prints {row['Derived']}. Fix the "
        "cell or the axis definition — never the printed number."
    )


@pytest.mark.parametrize("row", ASSIGNMENTS, ids=ASSIGNMENT_IDS)
def test_shipped_matches_the_rule_in_code(row: dict[str, str]) -> None:
    """A documented severity that the code does not emit is a false document."""
    match = RULE_ID_RE.search(row["Rule"])
    assert match is not None
    rule_id = match.group(0)
    assert Severity(row["Shipped"].lower()) == _SHIPPED[rule_id], (
        f"{rule_id}: docs/severity.md ships {row['Shipped']} but "
        f"metadata.severity is {_SHIPPED[rule_id].value.upper()}"
    )


@pytest.mark.parametrize("row", ASSIGNMENTS, ids=ASSIGNMENT_IDS)
def test_deviations_declare_a_reason_and_a_link(row: dict[str, str]) -> None:
    """shipped != derived is legal only as a declared, linked override."""
    match = RULE_ID_RE.search(row["Rule"])
    assert match is not None
    rule_id = match.group(0)
    override = row["Override"]
    if row["Derived"] == row["Shipped"]:
        assert override == NONE_CELL, (
            f"{rule_id}: derived equals shipped, so there is nothing to override"
        )
        return
    reason = OVERRIDE_REASON_RE.match(override)
    assert reason is not None, (
        f"{rule_id}: derived {row['Derived']} but ships {row['Shipped']} with no "
        "override. Declare one — the derivation is never re-chosen to match."
    )
    assert reason.group(1) in OVERRIDE_REASONS, (
        f"{rule_id}: override reason {reason.group(1)!r} is not in the closed "
        f"list {sorted(OVERRIDE_REASONS)}; extending it needs an ADR"
    )
    assert MARKDOWN_LINK_RE.search(override), (
        f"{rule_id}: override carries no link. The reasoning must be reachable, "
        "or the override is an assertion rather than a decision."
    )


def test_closed_reason_list_matches_the_document() -> None:
    """The list this test enforces is the list the document publishes."""
    documented = {
        cell.strip("`")
        for row in _table_after("## Calibration overrides")[1:]
        for cell in row[:1]
    }
    assert documented == set(OVERRIDE_REASONS)


def test_qualifier_list_matches_the_document() -> None:
    """The arithmetic this test applies is the arithmetic the document prints.

    ``ADJUSTMENTS`` is the only part of the model the suite hard-codes rather
    than reading back, so without this the page and the test could drift into
    agreeing about a rule while disagreeing about the rule that priced it —
    the failure mode the whole enforcement suite exists to remove.
    """
    documented: dict[str, int] = {}
    for row in _table_after("### Qualifiers and modifiers")[1:]:
        name = row[0].split("`")[1]
        documented[name] = -1 if "**down**" in row[1] else +1
    assert documented == {k: v for k, v in ADJUSTMENTS.items() if k != NONE_CELL}


DERIVATION_FIELD_RE = re.compile(
    r"^- \*\*(Baseline|Precondition|Impact|Qualifier/modifier|Derived|Shipped|"
    r"Scoping assumptions|Daemon assumptions|Evidence):\*\* (.+)$",
    re.MULTILINE,
)


def _derivation(rule_id: str) -> dict[str, str]:
    """Parse the derivation block from a rule's own doc page."""
    text = (RULE_DOCS / f"{rule_id}.md").read_text(encoding="utf-8")
    return {m.group(1): m.group(2).strip() for m in DERIVATION_FIELD_RE.finditer(text)}


@pytest.mark.parametrize("row", ASSIGNMENTS, ids=ASSIGNMENT_IDS)
def test_rule_page_derivation_matches_the_table(row: dict[str, str]) -> None:
    """The rule page and the assignment table must not drift apart.

    Both state the same derivation, so either can be edited alone — which is how
    ``severity.md`` came to disagree with the rules in the first place.
    """
    match = RULE_ID_RE.search(row["Rule"])
    assert match is not None
    rule_id = match.group(0)
    block = _derivation(rule_id)
    required = {
        "Baseline",
        "Precondition",
        "Impact",
        "Qualifier/modifier",
        "Derived",
        "Shipped",
        "Evidence",
    }
    assert required <= set(block), (
        f"{rule_id}: derivation block is missing {sorted(required - set(block))}"
    )

    assert block["Baseline"].startswith(row["Baseline"]), (
        f"{rule_id}: page says baseline {block['Baseline'][:1]!r}, "
        f"table says {row['Baseline']!r}"
    )
    for field, column in (("Precondition", "Precondition"), ("Impact", "Impact")):
        assert block[field].startswith(row[column]), (
            f"{rule_id}: page {field} is {block[field][:40]!r}, "
            f"table says {row[column]!r}"
        )
    qualifier = row["Qualifier"]
    expected_qualifier = "none" if qualifier == NONE_CELL else qualifier
    assert block["Qualifier/modifier"].startswith(expected_qualifier), (
        f"{rule_id}: page qualifier {block['Qualifier/modifier'][:40]!r} "
        f"disagrees with table {qualifier!r}"
    )
    assert block["Derived"].endswith(row["Derived"]), (
        f"{rule_id}: page derives {block['Derived']!r}, table says {row['Derived']}"
    )
    assert block["Shipped"].startswith(row["Shipped"]), (
        f"{rule_id}: page ships {block['Shipped'][:40]!r}, table says {row['Shipped']}"
    )
    if row["Override"] == NONE_CELL:
        assert "override" not in block["Shipped"], (
            f"{rule_id}: page declares an override the table does not carry"
        )
    else:
        reason = OVERRIDE_REASON_RE.match(row["Override"])
        assert reason is not None
        assert f"`{reason.group(1)}`" in block["Shipped"], (
            f"{rule_id}: page does not name the table's override reason "
            f"{reason.group(1)!r}"
        )


@pytest.mark.parametrize("row", ASSIGNMENTS, ids=ASSIGNMENT_IDS)
def test_row_links_resolve(row: dict[str, str]) -> None:
    """Relative links in the table point at files that exist."""
    for cell in (row["Rule"], row["Override"]):
        for target in MARKDOWN_LINK_RE.findall(cell):
            if target.startswith(("http://", "https://", "#")):
                continue
            assert (SEVERITY_DOC.parent / target).exists(), (
                f"{row['Rule']}: link target {target!r} does not exist"
            )
