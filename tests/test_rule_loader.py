"""Tests for rule auto-discovery via _load_rules.

Direct rule imports in other test files bypass `_load_rules`. Without
this test, mutmut survivors in the loader logic (e.g. dropping the
`startswith("CL")` filter) would go undetected.
"""

from __future__ import annotations

import sys

from compose_lint.rules import _load_rules, _registry, get_registered_rules


def test_load_rules_discovers_every_cl_module() -> None:
    """Re-running _load_rules from a cleared state must rediscover every
    CL-prefixed module and re-populate the registry. Kills mutants that
    drop the prefix filter, point at the wrong package path, or skip
    importlib.import_module entirely.
    """
    rule_modules = [
        name for name in list(sys.modules) if name.startswith("compose_lint.rules.CL")
    ]
    saved_modules = {name: sys.modules.pop(name) for name in rule_modules}
    saved_registry = list(_registry)
    _registry.clear()
    try:
        _load_rules()
        rule_ids = sorted(cls().metadata.id for cls in get_registered_rules())
        assert all(rid.startswith("CL-") for rid in rule_ids), rule_ids
        assert len(rule_ids) >= 19, f"expected >=19 rules, got {rule_ids}"
        assert len(rule_ids) == len(set(rule_ids)), f"duplicate rule IDs: {rule_ids}"
    finally:
        _registry.clear()
        _registry.extend(saved_registry)
        sys.modules.update(saved_modules)


def test_each_rule_id_is_unique() -> None:
    rule_ids = [cls().metadata.id for cls in get_registered_rules()]
    assert len(rule_ids) == len(set(rule_ids)), f"duplicate rule IDs: {rule_ids}"


def test_register_rule_appends_to_registry() -> None:
    from compose_lint.rules import BaseRule, register_rule

    before = len(get_registered_rules())

    class _ProbeRule(BaseRule):  # type: ignore[misc]
        @property
        def metadata(self):  # type: ignore[no-untyped-def]
            from compose_lint.models import RuleMetadata, Severity

            return RuleMetadata(
                id="CL-9999",
                name="probe",
                description="test-only",
                severity=Severity.LOW,
                references=["test"],
            )

        def check(self, *_args, **_kwargs):  # type: ignore[no-untyped-def]
            return iter(())

    register_rule(_ProbeRule)
    after = get_registered_rules()
    assert len(after) == before + 1
    assert _ProbeRule in after
    after.remove(_ProbeRule)
    from compose_lint.rules import _registry

    _registry.remove(_ProbeRule)
