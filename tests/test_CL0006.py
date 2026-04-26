"""Tests for CL-0006: No capability restrictions."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
from compose_lint.rules.CL0006_cap_drop import CapDropRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestCapDropRule:
    """Tests for capability restriction detection."""

    def setup_method(self) -> None:
        self.rule = CapDropRule()

    def test_detects_missing_cap_drop(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_cap_drop.yml")
        findings = list(
            self.rule.check("no_cap_drop", data["services"]["no_cap_drop"], data, lines)
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0006"
        assert findings[0].severity.value == "medium"

    def test_detects_partial_cap_drop(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_cap_drop.yml")
        findings = list(
            self.rule.check(
                "partial_cap_drop",
                data["services"]["partial_cap_drop"],
                data,
                lines,
            )
        )
        assert len(findings) == 1

    def test_cap_drop_all_clean(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_cap_drop.yml")
        findings = list(
            self.rule.check(
                "cap_drop_all", data["services"]["cap_drop_all"], data, lines
            )
        )
        assert len(findings) == 0

    def test_cap_drop_all_case_insensitive(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_cap_drop.yml")
        findings = list(
            self.rule.check(
                "cap_drop_all_lower",
                data["services"]["cap_drop_all_lower"],
                data,
                lines,
            )
        )
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = list(self.rule.check("app", {"image": "nginx"}, {}, {}))
        assert findings[0].fix is not None
        assert "cap_drop" in findings[0].fix

    def test_has_references(self) -> None:
        findings = list(self.rule.check("app", {"image": "nginx"}, {}, {}))
        assert len(findings[0].references) > 0
        assert "owasp" in findings[0].references[0].lower()

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0006"
        assert meta.severity.value == "medium"
        assert len(meta.references) > 0

    def test_safe_drop_all_add_safe_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "safe_cap_hardened.yml")
        findings = list(
            self.rule.check(
                "drop_all_add_safe",
                data["services"]["drop_all_add_safe"],
                data,
                lines,
            )
        )
        assert len(findings) == 0

    def test_safe_drop_all_lower_add_safe_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "safe_cap_hardened.yml")
        findings = list(
            self.rule.check(
                "drop_all_lower_add_safe",
                data["services"]["drop_all_lower_add_safe"],
                data,
                lines,
            )
        )
        assert len(findings) == 0
