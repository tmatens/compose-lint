"""Tests for CL-0015: Healthcheck explicitly disabled."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
from compose_lint.rules.CL0015_healthcheck_disabled import HealthcheckDisabledRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestHealthcheckDisabledRule:
    """Tests for healthcheck disabled detection."""

    def setup_method(self) -> None:
        self.rule = HealthcheckDisabledRule()

    def _check(self, service_name: str) -> list:
        data, lines = load_compose(FIXTURES / "insecure_healthcheck.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def test_detects_disabled(self) -> None:
        findings = self._check("disabled")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0015"
        assert "disabled" in findings[0].message.lower()

    def test_configured_no_findings(self) -> None:
        findings = self._check("configured")
        assert len(findings) == 0

    def test_no_healthcheck_no_findings(self) -> None:
        findings = self._check("no_healthcheck")
        assert len(findings) == 0

    def test_disable_false_no_findings(self) -> None:
        findings = self._check("disable_false")
        assert len(findings) == 0

    def test_detects_test_none_list(self) -> None:
        findings = self._check("disabled_via_test_list")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0015"
        assert 'test: ["NONE"]' in findings[0].message

    def test_detects_test_none_string(self) -> None:
        findings = self._check("disabled_via_test_string")
        assert len(findings) == 1
        assert 'test: ["NONE"]' in findings[0].message

    def test_test_none_lowercase_no_findings(self) -> None:
        findings = self._check("disabled_via_test_lowercase")
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = self._check("disabled")
        assert findings[0].fix is not None
        assert "healthcheck" in findings[0].fix.lower()

    def test_has_references(self) -> None:
        findings = self._check("disabled")
        assert len(findings[0].references) == 2

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0015"
        assert meta.severity.value == "low"

    def test_safe_cmd_shell_list_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "safe_healthcheck_cmd_shell.yml")
        findings = list(
            self.rule.check("cmd_shell", data["services"]["cmd_shell"], data, lines)
        )
        assert len(findings) == 0

    def test_safe_cmd_shell_string_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "safe_healthcheck_cmd_shell.yml")
        findings = list(
            self.rule.check(
                "cmd_shell_string",
                data["services"]["cmd_shell_string"],
                data,
                lines,
            )
        )
        assert len(findings) == 0
