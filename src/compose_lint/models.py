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
    suppressed: bool = False
    suppression_reason: str | None = None
    # The rule's own severity, recorded when `.compose-lint.yml` re-graded this
    # finding. `enabled: false` and `exclude_services` both leave a visible
    # record (a SUPPRESSED marker and a reason); `severity:` left none, so a
    # config could quietly downgrade a CRITICAL below the gate and the output
    # gave a reader no way to tell it apart from a rule that never fired that
    # hard. None means the rule's declared severity is what is shown.
    severity_overridden_from: Severity | None = None
    # The specific thing this finding is about, when a rule can fire more than
    # once for one service — the port spec, the device path, the mounted
    # source. It is the finding's *identity*, not its prose: SARIF
    # fingerprints are built from it so that rewording a message never
    # orphans a consumer's alerts (ADR-024). Rules that fire at most once per
    # service leave it None; `(file, rule, service)` already distinguishes
    # those. tests/test_finding_identity.py fails if a rule needs one and
    # does not set it.
    evidence: str | None = None
    # The file this finding's evidence was written in, when a run merged more
    # than one document (a base file plus its `compose.override.yml`) and that
    # file is not the one named in the report. None on a single-file run, which
    # is every run today, so no existing output shape changes.
    source_file: str | None = None
    # Whether `source_file` names a Compose *document* this run graded. False
    # when the evidence lives in a file the run merely read -- an `env_file:`
    # target, whose lines are deployed values rather than document text. The
    # text formatter never excerpts one: a credential rule's finding is about
    # the key, and printing the line would print the value the rule exists to
    # keep out of every output surface (ADR-027 §5). Deliberately not emitted
    # in JSON or SARIF -- it describes where the tool may look, not anything a
    # consumer grades, so the output contract does not move.
    source_is_document: bool = True


@dataclass(frozen=True)
class TextEdit:
    """A single text replacement produced by a rule's fixer (see ADR-014).

    Positions are 1-indexed and the region ``[start, end)`` is half-open,
    following the SARIF region convention. A zero-width region
    (``start == end``) is a pure insertion; an empty ``replacement`` is a pure
    deletion. ``caveat``, when set, names a runtime-behavior change the edit
    introduces and is surfaced in the dry-run diff and SARIF output.
    """

    start_line: int
    start_col: int
    end_line: int
    end_col: int
    replacement: str
    caveat: str | None = None
