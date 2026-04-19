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
            severity=Severity.MEDIUM,
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
                severity=Severity.MEDIUM,
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

    def test_disabled_rule_produces_suppressed_findings(self) -> None:
        data = {"services": {"web": {"test_flag": True}}}
        findings = run_rules(data, {}, disabled_rules={"CL-TEST": None})
        assert len(findings) == 1
        assert findings[0].suppressed is True
        assert findings[0].suppression_reason == "disabled in .compose-lint.yml"

    def test_disabled_rule_with_reason(self) -> None:
        data = {"services": {"web": {"test_flag": True}}}
        findings = run_rules(data, {}, disabled_rules={"CL-TEST": "SEC-1234 approved"})
        assert len(findings) == 1
        assert findings[0].suppressed is True
        assert findings[0].suppression_reason == "SEC-1234 approved"

    def test_suppressed_findings_excluded_from_filter(self) -> None:
        data = {"services": {"web": {"test_flag": True}}}
        findings = run_rules(data, {}, disabled_rules={"CL-TEST": None})
        filtered = filter_findings(findings, Severity.MEDIUM)
        assert len(filtered) == 0

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

    def test_excluded_service_produces_suppressed_finding(self) -> None:
        data = {
            "services": {
                "web": {"test_flag": True},
                "worker": {"test_flag": True},
            }
        }
        findings = run_rules(
            data,
            {},
            excluded_services={"CL-TEST": {"worker": "entrypoint switches users"}},
        )
        assert len(findings) == 2
        by_service = {f.service: f for f in findings}
        assert by_service["web"].suppressed is False
        assert by_service["worker"].suppressed is True
        assert by_service["worker"].suppression_reason == "entrypoint switches users"

    def test_excluded_service_without_reason(self) -> None:
        data = {"services": {"worker": {"test_flag": True}}}
        findings = run_rules(
            data,
            {},
            excluded_services={"CL-TEST": {"worker": None}},
        )
        assert len(findings) == 1
        assert findings[0].suppressed is True
        assert "worker" in (findings[0].suppression_reason or "")

    def test_excluded_service_only_affects_named_service(self) -> None:
        data = {
            "services": {
                "web": {"test_flag": True},
                "worker": {"test_flag": True},
            }
        }
        findings = run_rules(
            data,
            {},
            excluded_services={"CL-TEST": {"worker": None}},
        )
        assert len(findings) == 2
        suppressed = {f.service: f.suppressed for f in findings}
        assert suppressed == {"web": False, "worker": True}

    def test_global_disable_takes_precedence_over_per_service(self) -> None:
        """Per ADR-010: global disable wins over per-service exclusion."""
        data = {"services": {"worker": {"test_flag": True}}}
        findings = run_rules(
            data,
            {},
            disabled_rules={"CL-TEST": None},
            excluded_services={"CL-TEST": {"worker": "per-service reason"}},
        )
        assert len(findings) == 1
        assert findings[0].suppressed is True
        assert findings[0].suppression_reason == "disabled in .compose-lint.yml"

    def test_excluded_service_with_severity_override(self) -> None:
        """Severity overrides apply before suppression tagging."""
        data = {"services": {"worker": {"test_flag": True}}}
        findings = run_rules(
            data,
            {},
            severity_overrides={"CL-TEST": Severity.CRITICAL},
            excluded_services={"CL-TEST": {"worker": None}},
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].suppressed is True

    def test_excluded_unknown_service_is_noop(self) -> None:
        """Stale service names in config do not affect findings for real services."""
        data = {"services": {"web": {"test_flag": True}}}
        findings = run_rules(
            data,
            {},
            excluded_services={"CL-TEST": {"does-not-exist": "stale"}},
        )
        assert len(findings) == 1
        assert findings[0].service == "web"
        assert findings[0].suppressed is False


class TestFilterFindings:
    """Tests for filter_findings function."""

    def test_filters_below_threshold(self) -> None:
        findings = [
            Finding(
                rule_id="CL-TEST",
                severity=Severity.MEDIUM,
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
        filtered = filter_findings(findings, Severity.HIGH)
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
        filtered = filter_findings(findings, Severity.MEDIUM)
        assert len(filtered) == 1

    def test_none_above_threshold(self) -> None:
        findings = [
            Finding(
                rule_id="CL-TEST",
                severity=Severity.MEDIUM,
                service="web",
                message="warning",
            ),
        ]
        filtered = filter_findings(findings, Severity.CRITICAL)
        assert len(filtered) == 0
