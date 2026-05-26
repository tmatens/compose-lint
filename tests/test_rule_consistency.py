"""Consistency between each rule's ``metadata`` and the ``Finding``s it emits.

Every rule states its id and severity twice: once in ``RuleMetadata`` and
again in every ``Finding`` it constructs (see e.g.
``rules/CL0011_dangerous_cap_add.py``). Nothing structural ties the two
together, so a typo can desynchronise them silently. That matters most for
SARIF, where the rule descriptor's ``security-severity`` is derived from
``metadata.severity`` while each result's ``level`` comes from the emitted
``Finding.severity`` (``formatters/sarif.py``): a drift makes GitHub's
rule-level and alert-level severities disagree — the same class of bug #279
fixed for severity overrides. These tests turn such drift into a test failure
before rule ids and severities become permanent at 1.0.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint.models import Severity
from compose_lint.parser import ComposeError, load_compose, loads
from compose_lint.rules import get_registered_rules

if TYPE_CHECKING:
    from compose_lint.rules import BaseRule

FIXTURES = Path(__file__).parent / "compose_files"

RULE_ID_RE = re.compile(r"^CL-\d{4}$")

# Rules that deliberately raise a finding's severity above the documented
# baseline in ``metadata.severity``. Each value is the COMPLETE set of
# severities the rule may emit and must contain the metadata baseline:
#   CL-0011 raises ``cap_add: [ALL]`` from HIGH to CRITICAL.
#   CL-0013 raises a full host-root bind mount from HIGH to CRITICAL.
# Any other rule emitting a non-baseline severity is intentionally a failure
# below, so per-finding escalation stays a deliberate, reviewed decision.
VARIABLE_SEVERITY_RULES: dict[str, set[Severity]] = {
    "CL-0011": {Severity.HIGH, Severity.CRITICAL},
    "CL-0013": {Severity.HIGH, Severity.CRITICAL},
}

# Inline triggers for rules no committed fixture under ``compose_files/``
# exercises (CL-0022 is only covered by inline snippets in its own test).
# Extend this when a new rule's trigger isn't present as a fixture file.
INLINE_TRIGGERS: tuple[str, ...] = (
    "services:\n  tmpfs_exec:\n    image: nginx:1.27\n    tmpfs:\n      - /tmp:exec\n",
)

_RULES: list[BaseRule] = [cls() for cls in get_registered_rules()]
_RULE_IDS = [rule.metadata.id for rule in _RULES]


def _load_cases() -> list[tuple[str, dict[str, Any], dict[str, int]]]:
    """Compose inputs to drive every rule over: valid fixtures + inline triggers."""
    cases: list[tuple[str, dict[str, Any], dict[str, int]]] = []
    for path in sorted(FIXTURES.glob("*.yml")):
        if path.name.startswith("invalid"):
            continue  # parser-error fixtures are not lint inputs
        try:
            data, lines = load_compose(path)
        except ComposeError:
            continue
        if isinstance(data.get("services"), dict):
            cases.append((path.name, data, lines))
    for i, snippet in enumerate(INLINE_TRIGGERS):
        data, lines = loads(snippet)
        cases.append((f"<inline:{i}>", data, lines))
    return cases


_CASES = _load_cases()


@pytest.mark.parametrize("rule", _RULES, ids=_RULE_IDS)
def test_metadata_well_formed(rule: BaseRule) -> None:
    meta = rule.metadata
    assert RULE_ID_RE.match(meta.id), f"{meta.id!r} is not CL-NNNN"
    module_tag = rule.__class__.__module__.rsplit(".", 1)[-1].split("_", 1)[0]
    assert module_tag == meta.id.replace("-", ""), (
        f"{meta.id}: module {rule.__class__.__module__} disagrees with metadata id"
    )
    assert meta.name.strip(), f"{meta.id}: empty name"
    assert meta.description.strip(), f"{meta.id}: empty description"
    assert isinstance(meta.severity, Severity), f"{meta.id}: severity is not a Severity"
    assert meta.references, f"{meta.id}: no references"


def test_variable_severity_allow_list_is_honest() -> None:
    """The escalation allow-list must name real rules and include their baseline."""
    by_id = {rule.metadata.id: rule for rule in _RULES}
    for rule_id, allowed in VARIABLE_SEVERITY_RULES.items():
        assert rule_id in by_id, f"allow-list names unknown rule {rule_id}"
        assert len(allowed) > 1, f"{rule_id}: listed but declares a single severity"
        baseline = by_id[rule_id].metadata.severity
        assert baseline in allowed, (
            f"{rule_id}: metadata severity {baseline} not in declared set {allowed}"
        )


def test_findings_agree_with_metadata() -> None:
    """Every emitted finding's id and severity must match its rule's metadata.

    Driven rule-by-rule so the emitted ``Finding.rule_id`` is compared against
    the rule's own ``metadata.id`` (not against itself). Severity must equal
    the baseline, or fall in the declared escalation set for the two rules that
    vary it.
    """
    assert _CASES, "no usable compose fixtures found"
    fired: set[str] = set()
    total = 0
    for rule in _RULES:
        meta = rule.metadata
        allowed = VARIABLE_SEVERITY_RULES.get(meta.id, {meta.severity})
        for case_name, data, lines in _CASES:
            for service_name, service_config in data["services"].items():
                if not isinstance(service_config, dict):
                    continue
                for finding in rule.check(service_name, service_config, data, lines):
                    total += 1
                    fired.add(meta.id)
                    assert finding.rule_id == meta.id, (
                        f"{meta.id} emitted Finding.rule_id={finding.rule_id!r} "
                        f"in {case_name}"
                    )
                    assert finding.severity in allowed, (
                        f"{meta.id} emitted {finding.severity} in {case_name}; "
                        f"allowed: {sorted(s.value for s in allowed)}. If this "
                        "escalation is intended, declare it in "
                        "VARIABLE_SEVERITY_RULES."
                    )
                    assert finding.references, (
                        f"{meta.id} emitted a finding without references in {case_name}"
                    )
    assert total > 0, "fixtures triggered no findings"
    missing = set(_RULE_IDS) - fired
    assert not missing, (
        f"no test input exercises {sorted(missing)}; add a fixture under "
        "compose_files/ or an entry to INLINE_TRIGGERS so metadata/finding "
        "consistency is actually checked for it"
    )
