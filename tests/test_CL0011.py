"""Tests for CL-0011: Dangerous capabilities added."""

from __future__ import annotations

from pathlib import Path

from compose_lint.models import Severity
from compose_lint.parser import load_compose
from compose_lint.rules.CL0011_dangerous_cap_add import DangerousCapAddRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestDangerousCapAddRule:
    """Tests for dangerous cap_add detection."""

    def setup_method(self) -> None:
        self.rule = DangerousCapAddRule()

    def _check(self, service_name: str) -> list:
        data, lines = load_compose(FIXTURES / "insecure_cap_add.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def test_detects_sys_admin(self) -> None:
        findings = self._check("sys_admin")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0011"
        assert "SYS_ADMIN" in findings[0].message

    def test_detects_sys_ptrace(self) -> None:
        findings = self._check("sys_ptrace")
        assert len(findings) == 1
        assert "SYS_PTRACE" in findings[0].message

    def test_detects_net_admin(self) -> None:
        findings = self._check("net_admin")
        assert len(findings) == 1
        assert "NET_ADMIN" in findings[0].message

    def test_detects_multiple_dangerous(self) -> None:
        findings = self._check("multiple_dangerous")
        assert len(findings) == 3

    def test_safe_caps_no_findings(self) -> None:
        findings = self._check("safe_caps")
        assert len(findings) == 0

    def test_no_cap_add_no_findings(self) -> None:
        findings = self._check("no_cap_add")
        assert len(findings) == 0

    def test_lowercase_normalized(self) -> None:
        findings = self._check("lowercase_cap")
        assert len(findings) == 1
        assert "SYS_MODULE" in findings[0].message

    def test_all_seven_dangerous(self) -> None:
        findings = self._check("all_dangerous")
        assert len(findings) == 7

    def test_detects_cap_all_critical(self) -> None:
        findings = self._check("cap_all")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "ALL" in findings[0].message

    def test_detects_cap_all_lowercase(self) -> None:
        findings = self._check("cap_all_lowercase")
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "ALL" in findings[0].message

    def test_named_cap_still_high(self) -> None:
        findings = self._check("sys_admin")
        assert findings[0].severity == Severity.HIGH

    def test_has_fix_guidance(self) -> None:
        findings = self._check("sys_admin")
        assert findings[0].fix is not None
        assert "SYS_ADMIN" in findings[0].fix

    def test_has_references(self) -> None:
        findings = self._check("sys_admin")
        assert len(findings[0].references) > 0

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0011"
        assert meta.severity.value == "high"

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
