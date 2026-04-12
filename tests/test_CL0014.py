"""Tests for CL-0014: Logging driver disabled."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
from compose_lint.rules.CL0014_logging_disabled import LoggingDisabledRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestLoggingDisabledRule:
    """Tests for logging driver disabled detection."""

    def setup_method(self) -> None:
        self.rule = LoggingDisabledRule()

    def _check(self, service_name: str) -> list:
        data, lines = load_compose(FIXTURES / "insecure_logging.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def test_detects_driver_none(self) -> None:
        findings = self._check("logging_none")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0014"
        assert "none" in findings[0].message.lower()

    def test_detects_driver_none_case_insensitive(self) -> None:
        findings = self._check("logging_none_uppercase")
        assert len(findings) == 1

    def test_json_file_no_findings(self) -> None:
        findings = self._check("logging_json")
        assert len(findings) == 0

    def test_syslog_no_findings(self) -> None:
        findings = self._check("logging_syslog")
        assert len(findings) == 0

    def test_no_logging_config_no_findings(self) -> None:
        findings = self._check("no_logging_config")
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = self._check("logging_none")
        assert findings[0].fix is not None
        assert "json-file" in findings[0].fix

    def test_has_references(self) -> None:
        findings = self._check("logging_none")
        assert len(findings[0].references) > 0

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0014"
        assert meta.severity.value == "medium"
