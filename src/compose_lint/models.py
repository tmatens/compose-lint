"""Core data models for compose-lint findings and rule metadata."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.Enum):
    """Severity levels for lint findings, ordered by rank."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() >= other._rank()

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() > other._rank()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() <= other._rank()

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self._rank() < other._rank()

    def _rank(self) -> int:
        ranks = {
            Severity.LOW: 0,
            Severity.MEDIUM: 1,
            Severity.HIGH: 2,
            Severity.CRITICAL: 3,
        }
        return ranks[self]


@dataclass(frozen=True)
class RuleMetadata:
    """Metadata describing a lint rule."""

    id: str
    name: str
    description: str
    severity: Severity
    references: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Finding:
    """A single lint finding reported by a rule."""

    rule_id: str
    severity: Severity
    service: str
    message: str
    line: int | None = None
    fix: str | None = None
    references: list[str] = field(default_factory=list)
