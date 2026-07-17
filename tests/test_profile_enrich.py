"""Tests for profile-based fix enrichment (ADR-017)."""

from __future__ import annotations

from pathlib import Path

from compose_lint.engine import run_rules
from compose_lint.models import Finding, Severity
from compose_lint.profiles import load_catalog, match_profile
from compose_lint.profiles.enrich import enrich_fix

FIXTURE_CATALOG = Path(__file__).parent / "fixtures" / "profiles" / "catalog"


def _match(image: str):  # type: ignore[no-untyped-def]
    return match_profile(image, load_catalog(FIXTURE_CATALOG))


def _finding(
    rule_id: str, fix: str | None = None, references: list[str] | None = None
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.MEDIUM,
        service="db",
        message="finding",
        fix=fix,
        references=references or [],
    )


def test_cl0006_appends_capability_guidance() -> None:
    match = _match("postgres:16")
    assert match is not None
    result = enrich_fix(_finding("CL-0006"), match)
    assert result.fix is not None
    assert "profile hint" in result.fix
    assert "cap_add: [CHOWN" in result.fix


def test_cl0007_appends_filesystem_guidance() -> None:
    digest = "sha256:" + "c" * 64
    match = match_profile(
        f"lscr.io/linuxserver/radarr@{digest}", load_catalog(FIXTURE_CATALOG)
    )
    assert match is not None
    result = enrich_fix(_finding("CL-0007"), match)
    assert result.fix is not None
    assert "read_only: true" in result.fix


def test_unmapped_rule_is_untouched() -> None:
    match = _match("postgres:16")
    assert match is not None
    original = _finding("CL-0004", fix="pin the image")
    assert enrich_fix(original, match) is original


def test_missing_dimension_is_untouched() -> None:
    # The postgres fixture has no `devices` dimension (CL-0016's backing).
    match = _match("postgres:16")
    assert match is not None
    original = _finding("CL-0016", fix="review devices")
    assert enrich_fix(original, match) is original


def test_existing_fix_is_preserved_and_appended() -> None:
    match = _match("postgres:16")
    assert match is not None
    result = enrich_fix(_finding("CL-0006", fix="drop capabilities"), match)
    assert result.fix is not None
    assert result.fix.startswith("drop capabilities\n")
    assert "profile hint" in result.fix


def test_provenance_notes_confidence_and_precision() -> None:
    match = _match("postgres:16")  # tag-scoped profile -> TAG precision
    assert match is not None
    result = enrich_fix(_finding("CL-0006"), match)
    assert result.fix is not None
    assert "confidence high" in result.fix
    assert "tag match" in result.fix
    # attributed, not asserted as compose-lint fact (ADR-017 §7): the caveat
    # names the actual limit — a static linter can't see the runtime/invocation.
    assert "csd-derived" in result.fix
    assert "compose-lint can't see your runtime" in result.fix
    # digest is shortened, not the full 64 hex
    assert "a" * 64 not in result.fix


def test_reference_url_prepended_to_references() -> None:
    # The postgres fixture carries reference_url (schema 1.5); an enriched
    # finding gains it FIRST (text output shows only the first reference, and
    # the image-specific page outranks the rule's generic references).
    match = _match("postgres:16")
    assert match is not None
    rule_ref = "https://owasp.org/some-generic-guidance"
    result = enrich_fix(_finding("CL-0006", references=[rule_ref]), match)
    assert result.references == [
        "https://example.com/profiles/docker.io/library/postgres.html",
        rule_ref,
    ]


def test_no_reference_url_leaves_references_untouched() -> None:
    # The radarr fixture has no reference_url.
    digest = "sha256:" + "c" * 64
    match = match_profile(
        f"lscr.io/linuxserver/radarr@{digest}", load_catalog(FIXTURE_CATALOG)
    )
    assert match is not None
    rule_ref = "https://owasp.org/some-generic-guidance"
    result = enrich_fix(_finding("CL-0007", references=[rule_ref]), match)
    assert result.fix is not None  # still enriched
    assert result.references == [rule_ref]


def test_engine_enriches_when_lookup_supplied() -> None:
    data = {"services": {"db": {"image": "postgres:16"}}}
    findings = run_rules(data, {}, profile_lookup=_match)
    cl0006 = [f for f in findings if f.rule_id == "CL-0006"]
    assert cl0006
    assert "profile hint" in (cl0006[0].fix or "")


def test_engine_leaves_fix_untouched_without_lookup() -> None:
    data = {"services": {"db": {"image": "postgres:16"}}}
    findings = run_rules(data, {})
    cl0006 = [f for f in findings if f.rule_id == "CL-0006"]
    assert cl0006
    assert "profile hint" not in (cl0006[0].fix or "")
