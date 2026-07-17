"""Tests for catalog loading and profile matching (ADR-017)."""

from __future__ import annotations

import importlib.resources
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from jsonschema import Draft202012Validator

from compose_lint.profiles import (
    MatchPrecision,
    load_catalog,
    load_profile,
    match_profile,
)

if TYPE_CHECKING:
    from compose_lint.profiles.loader import Catalog

FIXTURE_CATALOG = Path(__file__).parent / "fixtures" / "profiles" / "catalog"


@pytest.fixture(scope="module")
def catalog() -> Catalog:
    return load_catalog(FIXTURE_CATALOG)


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    resource = (
        importlib.resources.files("compose_lint.profiles")
        / "schema"
        / "profile.schema.json"
    )
    return json.loads(resource.read_text(encoding="utf-8"))


def test_catalog_indexed_by_image_key(catalog: Catalog) -> None:
    assert "docker.io/library/postgres" in catalog
    assert "lscr.io/linuxserver/radarr" in catalog
    # Exploratory docs are loaded too (path is irrelevant; key is the image).
    assert "docker.io/library/nginx" in catalog


def test_every_fixture_is_schema_valid(
    catalog: Catalog, schema: dict[str, Any]
) -> None:
    validator = Draft202012Validator(schema)
    for image, doc in catalog.items():
        errors = list(validator.iter_errors(doc))
        assert not errors, (image, errors)


def test_no_catalog_configured_returns_empty() -> None:
    # No bundled catalog (ADR-017 §7): a None root yields an empty catalog.
    assert load_catalog(None) == {}


def test_match_by_repo_when_unpinned_service(catalog: Catalog) -> None:
    # postgres profile is tag-scoped, but a bare/untagged service still gets an
    # advisory repository-level match.
    match = match_profile("postgres", catalog)
    assert match is not None
    assert match.image == "docker.io/library/postgres"
    assert match.precision is MatchPrecision.REPO


def test_match_by_tag_glob(catalog: Catalog) -> None:
    match = match_profile("postgres:16.4", catalog)
    assert match is not None
    assert match.precision is MatchPrecision.TAG


def test_tag_outside_scope_is_stale(catalog: Catalog) -> None:
    # applies_to.tags = ["16", "16.*"]; a 15.x tag is out of scope -> no match.
    assert match_profile("postgres:15", catalog) is None


def test_match_by_digest(catalog: Catalog) -> None:
    digest = "sha256:" + "c" * 64
    match = match_profile(f"lscr.io/linuxserver/radarr@{digest}", catalog)
    assert match is not None
    assert match.precision is MatchPrecision.DIGEST


def test_digest_outside_scope_is_stale(catalog: Catalog) -> None:
    other = "sha256:" + "e" * 64
    assert match_profile(f"lscr.io/linuxserver/radarr@{other}", catalog) is None


def test_digest_pinned_profile_advisory_for_unpinned_service(catalog: Catalog) -> None:
    # radarr is digest-scoped; a service without a digest can't be checked
    # against it, so it falls back to an advisory repo match rather than None.
    match = match_profile("lscr.io/linuxserver/radarr", catalog)
    assert match is not None
    assert match.precision is MatchPrecision.REPO


def test_unknown_image_returns_none(catalog: Catalog) -> None:
    assert match_profile("docker.io/library/redis", catalog) is None


def test_dimensions_surfaced(catalog: Catalog) -> None:
    match = match_profile("postgres:16", catalog)
    assert match is not None
    assert "CHOWN" in match.dimensions["capabilities"]["cap_add"]


def test_reference_url_surfaced(catalog: Catalog) -> None:
    # postgres carries reference_url (schema 1.5); radarr does not.
    match = match_profile("postgres:16", catalog)
    assert match is not None
    assert (
        match.reference_url
        == "https://example.com/profiles/docker.io/library/postgres.html"
    )

    unset = match_profile("lscr.io/linuxserver/radarr", catalog)
    assert unset is not None
    assert unset.reference_url is None


def test_load_profile_returns_validated_only() -> None:
    # validated postgres resolves...
    assert load_profile("postgres:16", FIXTURE_CATALOG) is not None
    # ...but the exploratory nginx profile is never surfaced for enrichment.
    assert match_profile("nginx", load_catalog(FIXTURE_CATALOG)) is not None
    assert load_profile("nginx", FIXTURE_CATALOG) is None
