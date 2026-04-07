"""Tests for CL-0003: Privilege escalation not blocked."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
from compose_lint.rules.CL0003_no_new_privileges import NoNewPrivilegesRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestNoNewPrivilegesRule:
    """Tests for no-new-privileges detection."""

    def setup_method(self) -> None:
        self.rule = NoNewPrivilegesRule()

    def test_detects_missing_security_opt(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_no_new_priv.yml")
        findings = list(
            self.rule.check("missing", data["services"]["missing"], data, lines)
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0003"
        assert findings[0].severity.value == "warning"

    def test_detects_empty_security_opt(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_no_new_priv.yml")
        findings = list(
            self.rule.check(
                "empty_security_opt",
                data["services"]["empty_security_opt"],
                data,
                lines,
            )
        )
        assert len(findings) == 1

    def test_detects_other_opt_without_no_new_priv(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_no_new_priv.yml")
        findings = list(
            self.rule.check(
                "has_other_opt", data["services"]["has_other_opt"], data, lines
            )
        )
        assert len(findings) == 1

    def test_secure_service_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_no_new_priv.yml")
        findings = list(
            self.rule.check("secure", data["services"]["secure"], data, lines)
        )
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = list(self.rule.check("app", {"image": "nginx"}, {}, {}))
        assert findings[0].fix is not None
        assert "no-new-privileges" in findings[0].fix

    def test_has_references(self) -> None:
        assert len(self.rule.metadata.references) > 0
        assert "owasp" in self.rule.metadata.references[0].lower()
