"""Tests for CL-0012: PIDs cgroup limit disabled."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
from compose_lint.rules.CL0012_pids_limit import PidsLimitRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestPidsLimitRule:
    """Tests for PIDs cgroup limit detection."""

    def setup_method(self) -> None:
        self.rule = PidsLimitRule()

    def _check(self, service_name: str) -> list:
        data, lines = load_compose(FIXTURES / "insecure_pids_limit.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def test_detects_zero(self) -> None:
        findings = self._check("disabled_zero")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0012"
        assert "pids_limit: 0" in findings[0].message

    def test_detects_negative_one(self) -> None:
        findings = self._check("disabled_negative")
        assert len(findings) == 1
        assert "pids_limit: -1" in findings[0].message

    def test_positive_limit_no_findings(self) -> None:
        findings = self._check("positive_limit")
        assert len(findings) == 0

    def test_no_limit_set_no_findings(self) -> None:
        findings = self._check("no_limit_set")
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = self._check("disabled_zero")
        assert findings[0].fix is not None
        assert "200" in findings[0].fix

    def test_has_references(self) -> None:
        findings = self._check("disabled_zero")
        assert len(findings[0].references) > 0

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0012"
        assert meta.severity.value == "medium"
