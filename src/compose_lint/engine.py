"""Rule engine that runs registered rules against parsed Compose data."""

from __future__ import annotations

from typing import Any

from compose_lint.models import Finding, Severity
from compose_lint.rules import get_registered_rules


def run_rules(
    data: dict[str, Any],
    lines: dict[str, int],
    disabled_rules: dict[str, str | None] | None = None,
    severity_overrides: dict[str, Severity] | None = None,
) -> list[Finding]:
    """Run all registered rules against the parsed Compose data.

    Disabled rules are still executed but their findings are marked as
    suppressed. Returns a list of findings sorted by line number
    (None-line findings last).
    """
    disabled = disabled_rules or {}
    overrides = severity_overrides or {}
    findings: list[Finding] = []

    rule_classes = get_registered_rules()
    rules = [cls() for cls in rule_classes]

    services = data.get("services", {})

    for rule in rules:
        rule_id = rule.metadata.id
        is_suppressed = rule_id in disabled

        for service_name, service_config in services.items():
            for finding in rule.check(service_name, service_config, data, lines):
                if rule_id in overrides and not is_suppressed:
                    finding = Finding(
                        rule_id=finding.rule_id,
                        severity=overrides[rule_id],
                        service=finding.service,
                        message=finding.message,
                        line=finding.line,
                        fix=finding.fix,
                        references=finding.references,
                    )
                if is_suppressed:
                    reason = disabled[rule_id]
                    finding = Finding(
                        rule_id=finding.rule_id,
                        severity=finding.severity,
                        service=finding.service,
                        message=finding.message,
                        line=finding.line,
                        fix=finding.fix,
                        references=finding.references,
                        suppressed=True,
                        suppression_reason=reason
                        if reason
                        else "disabled in .compose-lint.yml",
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
