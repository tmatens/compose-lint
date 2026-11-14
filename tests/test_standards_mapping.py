"""The CIS and OWASP mapping, and its three surfaces: rules, docs and SARIF.

The mapping is published as tags that people filter on, so the failure worth
guarding is a quiet one: a rule citing a control the mapping does not list, a
tag the docs page does not show, or a rule that outgrows the ten tags GitHub
and GitLab keep. None of those fail in normal use.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from compose_lint import standards
from compose_lint.attack import ATTACK_VERSION, RULE_TECHNIQUES
from compose_lint.formatters.sarif import build_sarif_log, format_findings
from compose_lint.models import Finding, Severity
from compose_lint.rules import get_registered_rules

DOCS = Path(__file__).parent.parent / "docs"
STANDARDS_PAGE = (DOCS / "standards.md").read_text(encoding="utf-8")

RULE_REFERENCES = {
    cls().metadata.id: cls().metadata.references for cls in get_registered_rules()
}
RULE_IDS = sorted(RULE_REFERENCES)

_TAG = re.compile(
    r"^external/(?:"
    r"cis-docker/\d+\.\d+"
    r"|owasp-docker/rule-\d+[a-z]?"
    r"|mitre-attack/T\d{4}(?:\.\d{3})?"
    r")$"
)


@pytest.mark.parametrize(
    ("mapping", "unmapped"),
    [
        (standards.RULE_CIS, standards.CIS_UNMAPPED_BY_DESIGN),
        (standards.RULE_OWASP, standards.OWASP_UNMAPPED_BY_DESIGN),
    ],
    ids=["cis", "owasp"],
)
def test_every_rule_is_mapped_or_explained(
    mapping: dict[str, tuple[object, ...]], unmapped: dict[str, str]
) -> None:
    assert not set(mapping) & set(unmapped), "a rule is both mapped and unmapped"
    assert set(mapping) | set(unmapped) == set(RULE_IDS), (
        "Every rule is either mapped or listed with the reason none fits. "
        f"Missing: {sorted(set(RULE_IDS) - set(mapping) - set(unmapped))}. "
        f"Unknown: {sorted((set(mapping) | set(unmapped)) - set(RULE_IDS))}."
    )
    assert all(unmapped.values()), "an unmapped rule needs its reason"


def test_one_control_id_has_one_title() -> None:
    cis: dict[str, str] = {}
    for controls in standards.RULE_CIS.values():
        for control in controls:
            assert cis.setdefault(control.id, control.title) == control.title
    owasp: dict[str, str] = {}
    for rules in standards.RULE_OWASP.values():
        for rule in rules:
            assert owasp.setdefault(rule.id, rule.anchor) == rule.anchor
            assert rule.anchor.startswith(f"rule-{rule.id}-")


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_references_agree_with_the_mapping(rule_id: str) -> None:
    """A rule's prose citations and the structured mapping are one claim."""
    references = RULE_REFERENCES[rule_id]
    cited_cis = sorted(ref for ref in references if ref.startswith("CIS "))
    mapped_cis = sorted(c.reference for c in standards.RULE_CIS.get(rule_id, ()))
    assert cited_cis == mapped_cis

    cited_owasp = sorted(
        ref for ref in references if ref.startswith(standards.OWASP_DOCKER_URL)
    )
    mapped_owasp = sorted(r.reference for r in standards.RULE_OWASP.get(rule_id, ()))
    assert cited_owasp == mapped_owasp


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_tags_are_well_formed_and_within_the_limit(rule_id: str) -> None:
    tags = standards.rule_tags(rule_id)
    assert tags, f"{rule_id} has no tag from any source"
    assert len(tags) == len(set(tags))
    assert all(_TAG.match(tag) for tag in tags), tags
    assert len(tags) <= standards.MAX_TAGS_PER_RULE, (
        f"{rule_id} has {len(tags)} tags and GitHub keeps "
        f"{standards.MAX_TAGS_PER_RULE} without saying which. Decide which "
        "one this rule gives up before adding another."
    )


def test_tags_cover_all_three_sources_in_order() -> None:
    assert standards.rule_tags("CL-0002") == [
        "external/cis-docker/5.5",
        "external/owasp-docker/rule-3",
        "external/mitre-attack/T1611",
        "external/mitre-attack/T1685",
    ]


def test_no_security_tag() -> None:
    """Left out on purpose: `security-severity` already marks the result."""
    assert all("security" not in standards.rule_tags(r) for r in RULE_IDS)


class TestSarifTags:
    def setup_method(self) -> None:
        self.rules = build_sarif_log([])["runs"][0]["tool"]["driver"]["rules"]

    def test_each_descriptor_carries_its_tags(self) -> None:
        for rule in self.rules:
            assert rule["properties"]["tags"] == standards.rule_tags(rule["id"])

    def test_tags_do_not_displace_security_severity(self) -> None:
        for rule in self.rules:
            assert "security-severity" in rule["properties"]

    def test_tags_are_not_an_input_to_the_fingerprint(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Tagging must not close and reopen every consumer's alerts (ADR-024)."""
        finding = Finding(
            rule_id="CL-0002",
            severity=Severity.CRITICAL,
            service="web",
            message="m",
            line=3,
            evidence="privileged",
        )
        results = format_findings([finding], "compose.yml")
        tagged = build_sarif_log(results)
        monkeypatch.setattr(
            "compose_lint.formatters.sarif.rule_tags", lambda _rule_id: []
        )
        untagged = build_sarif_log(format_findings([finding], "compose.yml"))

        def fingerprints(log: dict[str, Any]) -> list[dict[str, str]]:
            return [r["partialFingerprints"] for r in log["runs"][0]["results"]]

        assert (
            "tags"
            not in untagged["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
        )
        assert fingerprints(tagged) == fingerprints(untagged)
        assert fingerprints(tagged)[0]


class TestStandardsPage:
    @pytest.mark.parametrize("rule_id", RULE_IDS)
    def test_page_lists_every_tag_of_every_rule(self, rule_id: str) -> None:
        row = next(
            line
            for line in STANDARDS_PAGE.splitlines()
            if line.startswith(f"| [{rule_id}](rules/{rule_id}.md) |")
        )
        assert re.findall(r"`(external/[^`]+)`", row) == standards.rule_tags(rule_id)

    def test_page_states_the_pinned_versions_and_counts(self) -> None:
        total = len(RULE_IDS)
        assert f"| v{standards.CIS_DOCKER_VERSION} |" in STANDARDS_PAGE
        assert f"| v{ATTACK_VERSION} |" in STANDARDS_PAGE
        assert f"| {len(standards.RULE_CIS)} of {total} |" in STANDARDS_PAGE
        assert f"| {len(standards.RULE_OWASP)} of {total} |" in STANDARDS_PAGE
        assert f"| {len(RULE_TECHNIQUES)} of {total} |" in STANDARDS_PAGE

    def test_page_gives_each_unmapped_rule_its_reason(self) -> None:
        for unmapped in (
            standards.CIS_UNMAPPED_BY_DESIGN,
            standards.OWASP_UNMAPPED_BY_DESIGN,
        ):
            for rule_id, reason in unmapped.items():
                assert f"- **{rule_id}**: {reason}." in STANDARDS_PAGE

    def test_severity_page_names_the_same_cis_version(self) -> None:
        severity = (DOCS / "severity.md").read_text(encoding="utf-8")
        assert f"Benchmark v{standards.CIS_DOCKER_VERSION}**" in severity


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_page_says_what_a_reference_claims(rule_id: str) -> None:
    """A reader who lands on a rule page sees the caveat, not only the list."""
    page = (DOCS / "rules" / f"{rule_id}.md").read_text(encoding="utf-8")
    after_references = page.split("**References:**")[-1]
    assert "does not mean a file with no finding complies" in " ".join(
        after_references.split()
    )
    assert "[Standards mapping](../standards.md)" in after_references
