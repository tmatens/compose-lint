"""Security profile catalog (see docs/adr/017-security-profile-catalog.md).

Holds the canonical profile JSON Schema (``schema/``), the derived-profile
catalog (``catalog/``), and the loader that matches a service image to a
profile. Enrichment wiring into the rules is a follow-up PR; nothing here is
called at lint time yet.
"""

from __future__ import annotations

from compose_lint.profiles.loader import load_catalog, load_profile, match_profile
from compose_lint.profiles.models import MatchPrecision, ProfileMatch
from compose_lint.profiles.refs import ImageRef, normalize_repository, parse_image_ref

__all__ = [
    "ImageRef",
    "MatchPrecision",
    "ProfileMatch",
    "load_catalog",
    "load_profile",
    "match_profile",
    "normalize_repository",
    "parse_image_ref",
]
