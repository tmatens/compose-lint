"""Tests for CL-0018: Explicit root user."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
from compose_lint.rules.CL0018_explicit_root import ExplicitRootRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestExplicitRootRule:
    """Tests for explicit root user detection."""

    def setup_method(self) -> None:
        self.rule = ExplicitRootRule()

    def _check(self, service_name: str) -> list:
        data, lines = load_compose(FIXTURES / "insecure_root_user.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def test_detects_root_name(self) -> None:
        findings = self._check("root_name")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0018"
        assert "root" in findings[0].message

    def test_detects_root_uid(self) -> None:
        findings = self._check("root_uid")
        assert len(findings) == 1

    def test_detects_root_with_group(self) -> None:
        findings = self._check("root_with_group")
        assert len(findings) == 1

    def test_detects_root_uid_gid(self) -> None:
        findings = self._check("root_uid_gid")
        assert len(findings) == 1

    def test_non_root_no_findings(self) -> None:
        findings = self._check("non_root")
        assert len(findings) == 0

    def test_named_user_no_findings(self) -> None:
        findings = self._check("named_user")
        assert len(findings) == 0

    def test_no_user_no_findings(self) -> None:
        findings = self._check("no_user")
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = self._check("root_name")
        assert findings[0].fix is not None
        assert "1000" in findings[0].fix

    def test_has_references(self) -> None:
        findings = self._check("root_name")
        assert len(findings[0].references) > 0

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0018"
        assert meta.severity.value == "medium"
