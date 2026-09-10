"""Load the prose documentation for a single rule.

The per-rule markdown lives in `docs/rules/CL-XXXX.md` in the repo and is
force-included into the wheel at `compose_lint/rule_docs/CL-XXXX.md` (see
`pyproject.toml`). Editable installs and direct source checkouts miss the
packaged copy, so this module probes the source layout as a fallback.
"""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path

_RULE_ID_RE = re.compile(r"^CL-\d{4}$")

# Ids that were used and retired. They must not reappear: reusing one
# silently rewrites the meaning of a suppression someone already wrote
# (ADR-005). Shared with tests/test_rule_surfaces.py.
FALLOW_RULE_IDS = frozenset({"CL-0012", "CL-0015", "CL-0023"})


class UnknownRuleError(ValueError):
    """Raised when a rule id cannot be explained.

    ``kind`` is ``malformed`` (not CL-XXXX), ``retired`` (fallow under
    ADR-028), or ``unknown`` (well-formed, no such rule).
    """

    def __init__(self, rule_id: str, *, kind: str) -> None:
        super().__init__(rule_id)
        self.rule_id = rule_id
        self.kind = kind


def normalize_rule_id(raw: str) -> str:
    """Normalize a user-supplied rule id to the canonical `CL-NNNN` form.

    Accepts any case and surrounding whitespace. Rejects anything that
    does not match the zero-padded four-digit scheme from ADR-005.
    """
    candidate = raw.strip().upper()
    if not _RULE_ID_RE.match(candidate):
        raise UnknownRuleError(raw, kind="malformed")
    return candidate


def load_rule_doc(rule_id: str) -> str:
    """Return the markdown body of `docs/rules/<rule_id>.md`.

    Looks first in the installed package (wheel path), then falls back to
    the repo's `docs/rules/` directory so `pip install -e .` and source
    checkouts keep working.
    """
    canonical = normalize_rule_id(rule_id)
    filename = f"{canonical}.md"

    packaged = resources.files("compose_lint").joinpath("rule_docs", filename)
    if packaged.is_file():
        return packaged.read_text(encoding="utf-8")

    repo_copy = Path(__file__).resolve().parents[2] / "docs" / "rules" / filename
    if repo_copy.is_file():
        return repo_copy.read_text(encoding="utf-8")

    if canonical in FALLOW_RULE_IDS:
        raise UnknownRuleError(canonical, kind="retired")
    raise UnknownRuleError(canonical, kind="unknown")
