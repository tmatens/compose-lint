"""Load and match security profiles from a catalog (ADR-017 §7).

There is **no built-in catalog**: compose-lint ships the machinery, not the
data. Profiles come from a directory the user configures (``profiles.path``) and
trusts — see ADR-017 §7. ``load_profile`` is the consumer entry point used by
enrichment: it returns only *validated* matches, because exploratory profiles
are review material and must never drive guidance. ``match_profile`` and
``load_catalog`` are lower-level and surface any status, for tooling and tests.

Runtime dependency stays PyYAML only; documents are trusted to be schema-valid
because the catalog's own CI validates them (see ``scripts/validate_profiles.py``).
"""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from pathlib import Path

from compose_lint.profiles.models import MatchPrecision, ProfileMatch
from compose_lint.profiles.refs import ImageRef, parse_image_ref

Catalog = dict[str, dict[str, Any]]


def _read_catalog_dir(root: Path) -> Catalog:
    catalog: Catalog = {}
    if not root.is_dir():
        return catalog
    for path in sorted(root.rglob("*.y*ml")):
        if not path.is_file():
            continue
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and isinstance(doc.get("image"), str):
            catalog[doc["image"]] = doc
    return catalog


def load_catalog(root: Path | None) -> Catalog:
    """Load all catalog documents under ``root``, indexed by canonical ``image``.

    Returns ``{}`` when ``root`` is ``None`` (no catalog configured) or not a
    directory. There is no bundled default — the catalog is a user-configured,
    external source (ADR-017 §7).
    """
    if root is None:
        return {}
    return _read_catalog_dir(root)


def _precision(ref: ImageRef, doc: Mapping[str, Any]) -> MatchPrecision | None:
    """Resolve match precision, or None when the profile is stale for this ref.

    A profile pinned via ``applies_to`` that explicitly disagrees with the
    service's digest or tag is treated as *stale* (no match) rather than applied
    to an artifact it was never validated against. An unscoped profile, or a
    service too unpinned to check, matches at advisory REPO precision.
    """
    applies = doc.get("applies_to")
    if not isinstance(applies, Mapping):
        return MatchPrecision.REPO

    digests = applies.get("digests")
    if ref.digest is not None and isinstance(digests, list) and digests:
        return MatchPrecision.DIGEST if ref.digest in digests else None

    tags = applies.get("tags")
    if ref.tag is not None and isinstance(tags, list) and tags:
        matched = any(fnmatch.fnmatch(ref.tag, str(pat)) for pat in tags)
        return MatchPrecision.TAG if matched else None

    return MatchPrecision.REPO


def match_profile(image: str, catalog: Catalog) -> ProfileMatch | None:
    """Resolve a profile for ``image`` from ``catalog``, of any status."""
    ref = parse_image_ref(image)
    doc = catalog.get(ref.repository)
    if doc is None:
        return None

    precision = _precision(ref, doc)
    if precision is None:
        return None

    dimensions = doc.get("dimensions")
    return ProfileMatch(
        image=ref.repository,
        status=str(doc.get("status", "")),
        precision=precision,
        dimensions=dimensions if isinstance(dimensions, dict) else {},
    )


def load_profile(image: str, catalog_root: Path | None) -> ProfileMatch | None:
    """Return the *validated* profile for ``image`` from the catalog at
    ``catalog_root``, or None.

    Exploratory profiles are intentionally not surfaced here (ADR-017); they are
    below-bar review material and must not drive enrichment.
    """
    match = match_profile(image, load_catalog(catalog_root))
    if match is None or not match.is_validated:
        return None
    return match
