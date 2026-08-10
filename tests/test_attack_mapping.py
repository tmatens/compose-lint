"""The ATT&CK mapping, and its two surfaces: rule docs and SARIF.

The mapping is published to a security audience that will check it, so the
failure mode worth guarding is not "a rule is unmapped" — it is a mapping that
has quietly drifted from the docs, or a SARIF relationship pointing at a taxa
entry that is not there. Both are silent in normal use.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from compose_lint.attack import (
    ATTACK_VERSION,
    ENABLED_ONLY,
    RULE_TECHNIQUES,
    all_techniques,
)
from compose_lint.formatters.sarif import build_sarif_log
from compose_lint.rules import get_registered_rules

RULE_DOCS = Path(__file__).parent.parent / "docs" / "rules"

RULE_IDS = sorted(cls().metadata.id for cls in get_registered_rules())

# Rules with no adversary technique, each for a stated reason. This is an
# allow-list rather than a silent gap: CL-0005's absence is *evidence* used in
# its override, so an unexplained addition here would erase an argument.
UNMAPPED_BY_DESIGN = {
    "CL-0005": "attack surface that enables T1190; no technique of its own",
    "CL-0007": "defence-in-depth — denies tool staging, too indirect to name",
    "CL-0022": "defence-in-depth — same reasoning as CL-0007",
}


def test_every_rule_is_mapped_or_explained() -> None:
    mapped = set(RULE_TECHNIQUES)
    unexplained = set(RULE_IDS) - mapped - set(UNMAPPED_BY_DESIGN)
    assert not unexplained, (
        f"unmapped with no stated reason: {sorted(unexplained)}. Either map the "
        "rule or record why no technique fits."
    )
    stale = mapped - set(RULE_IDS)
    assert not stale, f"mapping names rules that no longer exist: {sorted(stale)}"


def test_unmapped_allow_list_is_honest() -> None:
    """An entry here must name a real rule that is genuinely unmapped."""
    for rule_id in UNMAPPED_BY_DESIGN:
        assert rule_id in RULE_IDS, f"allow-list names unknown rule {rule_id}"
        assert rule_id not in RULE_TECHNIQUES, (
            f"{rule_id} is both mapped and listed as unmapped"
        )


def test_technique_ids_are_internally_consistent() -> None:
    """One id, one name — a duplicate with a different name is a typo."""
    names: dict[str, str] = {}
    for techniques in RULE_TECHNIQUES.values():
        for technique in techniques:
            assert names.setdefault(technique.id, technique.name) == technique.name, (
                f"{technique.id} appears with two names"
            )
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", technique.id), technique.id
            assert technique.url.startswith("https://attack.mitre.org/techniques/")


def test_enabled_only_is_kept_out_of_the_mapping() -> None:
    """Enabling a technique is not mitigating it; the two must not merge."""
    mapped_ids = {t.id for ts in RULE_TECHNIQUES.values() for t in ts}
    for rule_id, techniques in ENABLED_ONLY.items():
        assert rule_id not in RULE_TECHNIQUES
        for technique in techniques:
            assert technique.id not in mapped_ids


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_doc_matches_the_mapping(rule_id: str) -> None:
    """Every mapped technique appears on the page, and nothing extra does."""
    text = (RULE_DOCS / f"{rule_id}.md").read_text(encoding="utf-8")
    assert "## ATT&CK coverage" in text, f"{rule_id}: no ATT&CK section"
    section = text.split("## ATT&CK coverage", 1)[1]
    section = section.split("\n## ", 1)[0]

    documented = set(re.findall(r"\[(T\d{4}(?:\.\d{3})?) ", section))
    expected = {t.id for t in RULE_TECHNIQUES.get(rule_id, ())}
    expected |= {t.id for t in ENABLED_ONLY.get(rule_id, ())}
    assert documented == expected, (
        f"{rule_id}: page lists {sorted(documented)}, mapping says {sorted(expected)}"
    )
    # The version pin is stated alongside the mitigation table; a page whose
    # only entry is an "enables" note has no table to pin.
    if RULE_TECHNIQUES.get(rule_id):
        assert f"v{ATTACK_VERSION}" in section, (
            f"{rule_id}: ATT&CK section does not state the pinned version"
        )


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_enterprise_techniques_are_labelled_on_the_page(rule_id: str) -> None:
    """Containers-matrix blind spots must not read as Containers coverage."""
    text = (RULE_DOCS / f"{rule_id}.md").read_text(encoding="utf-8")
    section = text.split("## ATT&CK coverage", 1)[1].split("\n## ", 1)[0]
    for technique in RULE_TECHNIQUES.get(rule_id, ()):
        if technique.enterprise:
            row = next(
                line for line in section.splitlines() if f"[{technique.id} " in line
            )
            assert "Enterprise" in row, (
                f"{rule_id}: {technique.id} is Enterprise/Linux but the page "
                "presents it as Containers coverage"
            )


class TestSarifTaxonomy:
    def setup_method(self) -> None:
        self.run = build_sarif_log([])["runs"][0]
        self.taxonomy = self.run["taxonomies"][0]

    def test_taxonomy_is_declared_and_pinned(self) -> None:
        assert self.taxonomy["name"] == "MITRE ATT&CK"
        assert self.taxonomy["version"] == ATTACK_VERSION
        assert self.taxonomy["guid"]
        # We map a chosen subset, not the whole matrix — saying so is required
        # by the spec's semantics and honest besides.
        assert self.taxonomy["isComprehensive"] is False

    def test_taxa_cover_exactly_the_mapped_techniques(self) -> None:
        assert [t["id"] for t in self.taxonomy["taxa"]] == [
            t.id for t in all_techniques()
        ]

    def test_relationships_resolve_to_real_taxa(self) -> None:
        taxa = self.taxonomy["taxa"]
        for rule in self.run["tool"]["driver"]["rules"]:
            expected = {t.id for t in RULE_TECHNIQUES.get(rule["id"], ())}
            if not expected:
                assert "relationships" not in rule, rule["id"]
                continue
            targets = rule["relationships"]
            assert {t["target"]["id"] for t in targets} == expected, rule["id"]
            for target in targets:
                # The index must actually address the taxa entry it names.
                assert taxa[target["target"]["index"]]["id"] == target["target"]["id"]
                assert (
                    target["target"]["toolComponent"]["guid"] == (self.taxonomy["guid"])
                )

    def test_relationship_kind_claims_relevance_not_identity(self) -> None:
        """A rule mitigates a technique; it is not the technique."""
        for rule in self.run["tool"]["driver"]["rules"]:
            for target in rule.get("relationships", []):
                assert target["kinds"] == ["relevant"]
