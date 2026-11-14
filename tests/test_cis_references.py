"""CIS Docker Benchmark citations: one number, one control, and the page agrees.

Rule references cite CIS controls by number, and the numbers are pinned to one
benchmark version in `docs/severity.md`. Two rules once cited 5.10 for two
different controls, a rule page listed no CIS control while its rule cited two,
and a rule kept citing controls whose checks had been removed. None of that
failed a test. These do not check a number against the benchmark itself, which
is not redistributable; they check that the citations agree with each other
and with the rule pages.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from compose_lint.rules import get_registered_rules

REPO_ROOT = Path(__file__).resolve().parent.parent
RULE_DOCS = REPO_ROOT / "docs" / "rules"

_CIS_REF = re.compile(r"^CIS Docker Benchmark (\d+\.\d+) — (\S.*)$")
_DOC_CIS_LINE = re.compile(r"^- (CIS Docker Benchmark .*)$", re.MULTILINE)


def _rule_references() -> dict[str, list[str]]:
    references: dict[str, list[str]] = {}
    for cls in get_registered_rules():
        metadata = cls().metadata
        references[metadata.id] = [
            ref for ref in metadata.references if ref.startswith("CIS ")
        ]
    return references


def _doc_references(rule_id: str) -> list[str]:
    text = (RULE_DOCS / f"{rule_id}.md").read_text(encoding="utf-8")
    return _DOC_CIS_LINE.findall(text)


RULE_REFERENCES = _rule_references()


def test_every_cis_reference_names_one_control_with_its_title() -> None:
    malformed = [
        (rule_id, ref)
        for rule_id, refs in RULE_REFERENCES.items()
        for ref in refs
        if not _CIS_REF.match(ref)
    ]
    assert not malformed, (
        "A CIS reference is one control number and its title, "
        f"'CIS Docker Benchmark 5.4 — Ensure ...': {malformed}"
    )


def test_one_control_number_has_one_title() -> None:
    titles: dict[str, set[str]] = {}
    for rule_id, refs in RULE_REFERENCES.items():
        for ref in [*refs, *_doc_references(rule_id)]:
            match = _CIS_REF.match(ref)
            if match:
                # A page may add a note in parentheses after the title.
                title = re.sub(r"\s+\(.*\)$", "", match.group(2))
                titles.setdefault(match.group(1), set()).add(title)
    conflicts = {number: sorted(t) for number, t in titles.items() if len(t) > 1}
    assert not conflicts, (
        "The same CIS control number is cited with different titles, so at "
        f"least one number is wrong for the pinned benchmark: {conflicts}"
    )


@pytest.mark.parametrize("rule_id", sorted(RULE_REFERENCES))
def test_rule_page_lists_the_rules_cis_references(rule_id: str) -> None:
    on_page = _doc_references(rule_id)
    missing = [
        ref
        for ref in RULE_REFERENCES[rule_id]
        if not any(line.startswith(ref) for line in on_page)
    ]
    assert not missing, (
        f"docs/rules/{rule_id}.md does not list a CIS control the rule cites: {missing}"
    )
