"""Dataclasses for a matched security profile (ADR-017)."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Any


class MatchPrecision(enum.Enum):
    """How specifically a profile matched the service's image.

    DIGEST/TAG mean the service's pinned digest or tag was confirmed against the
    profile's ``applies_to``. REPO is a repository-level (advisory) match: the
    image matches but the profile carries no ``applies_to`` scope, or the
    service is unpinned, so the profile is guidance rather than an exact fit.
    """

    DIGEST = "digest"
    TAG = "tag"
    REPO = "repo"


@dataclass(frozen=True)
class ProfileMatch:
    """A catalog profile resolved for a specific service image."""

    image: str
    """Canonical repository match key (registry/namespace/name)."""

    status: str
    """``validated`` or ``exploratory`` (see ADR-017)."""

    precision: MatchPrecision
    dimensions: dict[str, Any]
    """Raw per-dimension blocks (capabilities, filesystem, ...)."""

    @property
    def is_validated(self) -> bool:
        return self.status == "validated"
