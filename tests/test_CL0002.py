"""Tests for CL-0002: Privileged mode enabled."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
from compose_lint.rules.CL0002_privileged_mode import PrivilegedModeRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestPrivilegedModeRule:
    """Tests for privileged mode detection."""

    def setup_method(self) -> None:
        self.rule = PrivilegedModeRule()

    def test_detects_privileged(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_privileged.yml")
        findings = list(self.rule.check("app", data["services"]["app"], data, lines))
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0002"
        assert findings[0].severity.value == "critical"

    def test_clean_service_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_privileged.yml")
        findings = list(
            self.rule.check("clean", data["services"]["clean"], data, lines)
        )
        assert len(findings) == 0

    def test_privileged_false_no_findings(self) -> None:
        findings = list(self.rule.check("app", {"privileged": False}, {}, {}))
        assert len(findings) == 0

    def test_no_privileged_key_no_findings(self) -> None:
        findings = list(self.rule.check("app", {"image": "nginx"}, {}, {}))
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_privileged.yml")
        findings = list(self.rule.check("app", data["services"]["app"], data, lines))
        assert findings[0].fix is not None
        assert "cap_drop" in findings[0].fix.lower()

    def test_has_references(self) -> None:
        assert len(self.rule.metadata.references) > 0
        assert "owasp" in self.rule.metadata.references[0].lower()
