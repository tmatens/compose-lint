"""Tests for the rule engine."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterator

from compose_lint.engine import filter_findings, run_rules
from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, _registry


class _DummyRule(BaseRule):
    """A test rule that flags any service with 'test_flag: true'."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-TEST",
            name="Test rule",
            description="Flags services with test_flag: true",
            severity=Severity.WARNING,
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        if service_config.get("test_flag") is True:
            yield Finding(
                rule_id="CL-TEST",
                severity=Severity.WARNING,
                service=service_name,
                message="test_flag is set",
                line=lines.get(f"services.{service_name}.test_flag"),
            )


class TestRunRules:
    """Tests for run_rules function."""

    def setup_method(self) -> None:
        self._saved_registry = list(_registry)
        _registry.clear()
        _registry.append(_DummyRule)

    def teardown_method(self) -> None:
        _registry.clear()
        _registry.extend(self._saved_registry)

    def test_finds_flagged_service(self) -> None:
        data = {"services": {"web": {"test_flag": True}}}
        findings = run_rules(data, {})
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-TEST"
        assert findings[0].service == "web"

    def test_skips_clean_service(self) -> None:
        data = {"services": {"web": {"image": "nginx"}}}
        findings = run_rules(data, {})
        assert len(findings) == 0

    def test_multiple_services(self) -> None:
        data = {
            "services": {
                "web": {"test_flag": True},
                "db": {"image": "postgres"},
                "worker": {"test_flag": True},
            }
        }
        findings = run_rules(data, {})
        assert len(findings) == 2
        services = {f.service for f in findings}
        assert services == {"web", "worker"}

    def test_disabled_rule(self) -> None:
        data = {"services": {"web": {"test_flag": True}}}
        findings = run_rules(data, {}, disabled_rules={"CL-TEST"})
        assert len(findings) == 0

    def test_severity_override(self) -> None:
        data = {"services": {"web": {"test_flag": True}}}
        findings = run_rules(
            data, {}, severity_overrides={"CL-TEST": Severity.CRITICAL}
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_sorted_by_line_number(self) -> None:
        data = {
            "services": {
                "web": {"test_flag": True},
                "db": {"test_flag": True},
            }
        }
        lines = {
            "services.db.test_flag": 3,
            "services.web.test_flag": 10,
        }
        findings = run_rules(data, lines)
        assert findings[0].line == 3
        assert findings[1].line == 10

    def test_empty_services(self) -> None:
        data = {"services": {}}
        findings = run_rules(data, {})
        assert len(findings) == 0


class TestFilterFindings:
    """Tests for filter_findings function."""

    def test_filters_below_threshold(self) -> None:
        findings = [
            Finding(
                rule_id="CL-TEST",
                severity=Severity.WARNING,
                service="web",
                message="warning",
            ),
            Finding(
                rule_id="CL-TEST",
                severity=Severity.CRITICAL,
                service="web",
                message="critical",
            ),
        ]
        filtered = filter_findings(findings, Severity.ERROR)
        assert len(filtered) == 1
        assert filtered[0].severity == Severity.CRITICAL

    def test_all_above_threshold(self) -> None:
        findings = [
            Finding(
                rule_id="CL-TEST",
                severity=Severity.CRITICAL,
                service="web",
                message="critical",
            ),
        ]
        filtered = filter_findings(findings, Severity.WARNING)
        assert len(filtered) == 1

    def test_none_above_threshold(self) -> None:
        findings = [
            Finding(
                rule_id="CL-TEST",
                severity=Severity.WARNING,
                service="web",
                message="warning",
            ),
        ]
        filtered = filter_findings(findings, Severity.CRITICAL)
        assert len(filtered) == 0
