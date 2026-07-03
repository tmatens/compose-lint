"""Security profile machinery (see docs/adr/017-security-profile-catalog.md).

Holds the canonical profile JSON Schema (``schema/``) and the loader that
matches a service image to a profile. Per ADR-017 §7 there is **no bundled
catalog** — profiles come from a user-configured external source
(``profiles.path``); compose-lint ships the machinery, not the data.
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
