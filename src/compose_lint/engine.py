"""Rule engine that runs registered rules against parsed Compose data."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from compose_lint.models import Finding, Severity
from compose_lint.rules import get_registered_rules


def run_rules(
    data: dict[str, Any],
    lines: dict[str, int],
    disabled_rules: dict[str, str | None] | None = None,
    severity_overrides: dict[str, Severity] | None = None,
    excluded_services: dict[str, dict[str, str | None]] | None = None,
) -> list[Finding]:
    """Run all registered rules against the parsed Compose data.

    Disabled rules and per-service exclusions still produce findings, but
    those findings are marked suppressed with an appropriate reason. A
    global disable takes precedence over per-service exclusions (see
    ADR-010). Returns findings sorted by line number (None-line last).
    """
    disabled = disabled_rules or {}
    overrides = severity_overrides or {}
    excluded = excluded_services or {}
    findings: list[Finding] = []

    rule_classes = get_registered_rules()
    rules = [cls() for cls in rule_classes]

    services = data.get("services", {})

    for rule in rules:
        rule_id = rule.metadata.id
        is_suppressed = rule_id in disabled
        rule_excluded = excluded.get(rule_id, {})

        for service_name, service_config in services.items():
            for finding in rule.check(service_name, service_config, data, lines):
                if rule_id in overrides and not is_suppressed:
                    finding = replace(finding, severity=overrides[rule_id])
                if is_suppressed:
                    reason = disabled[rule_id]
                    finding = replace(
                        finding,
                        suppressed=True,
                        suppression_reason=reason or "disabled in .compose-lint.yml",
                    )
                elif service_name in rule_excluded:
                    reason = rule_excluded[service_name]
                    default = (
                        f"excluded for service '{service_name}' in .compose-lint.yml"
                    )
                    finding = replace(
                        finding,
                        suppressed=True,
                        suppression_reason=reason or default,
                    )
                findings.append(finding)

    findings.sort(key=lambda f: (f.line is None, f.line or 0))
    return findings


def filter_findings(
    findings: list[Finding],
    severity_threshold: Severity = Severity.HIGH,
) -> list[Finding]:
    """Filter findings to only those at or above the severity threshold.

    Suppressed findings are excluded regardless of severity.
    """
    return [
        f for f in findings if f.severity >= severity_threshold and not f.suppressed
    ]
