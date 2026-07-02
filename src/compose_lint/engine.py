"""Rule engine that runs registered rules against parsed Compose data."""

from __future__ import annotations

import sys
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, Severity
from compose_lint.profiles.enrich import enrich_fix
from compose_lint.rules import get_registered_rules

if TYPE_CHECKING:
    from collections.abc import Callable

    from compose_lint.profiles.models import ProfileMatch


def _default_rule_error(rule_id: str, service_name: str, exc: Exception) -> None:
    """Report a crashed rule to stderr without aborting the run."""
    print(
        f"Error: rule {rule_id} failed on service '{service_name}': "
        f"{type(exc).__name__}: {exc}",
        file=sys.stderr,
    )


def run_rules(
    data: dict[str, Any],
    lines: dict[str, int],
    disabled_rules: dict[str, str | None] | None = None,
    severity_overrides: dict[str, Severity] | None = None,
    excluded_services: dict[str, dict[str, str | None]] | None = None,
    on_error: Callable[[str, str, Exception], None] | None = None,
    profile_lookup: Callable[[str], ProfileMatch | None] | None = None,
) -> list[Finding]:
    """Run all registered rules against the parsed Compose data.

    Disabled rules and per-service exclusions still produce findings, but
    those findings are marked suppressed with an appropriate reason. A
    global disable takes precedence over per-service exclusions (see
    ADR-010). Returns findings sorted by line number (None-line last).

    A rule that raises is isolated rather than allowed to abort the whole
    run: the failure is reported via ``on_error`` (defaulting to a stderr
    diagnostic) and the engine continues with the next service and rule. The
    CLI maps such a failure to exit 2 ("compose-lint itself couldn't run",
    ADR-006) so a directory sweep is never silently truncated and a crash is
    never mistaken for a clean lint failure.

    When ``profile_lookup`` is supplied, each service's image is resolved to a
    validated csd-derived profile (ADR-017) and matching findings get
    image-specific guidance appended to their ``fix`` text. This is purely
    additive — the set and classification of findings is unchanged.
    """
    disabled = disabled_rules or {}
    overrides = severity_overrides or {}
    excluded = excluded_services or {}
    report_error = on_error if on_error is not None else _default_rule_error
    findings: list[Finding] = []

    rule_classes = get_registered_rules()
    rules = [cls() for cls in rule_classes]

    services = data.get("services", {})

    # Resolve each service's derived profile once (ADR-017). Enrichment only
    # appends image-specific guidance to a finding's fix text; it never changes
    # which findings are produced. Off unless profile_lookup is supplied.
    service_matches: dict[str, ProfileMatch | None] = {}
    if profile_lookup is not None:
        for service_name, service_config in services.items():
            image = (
                service_config.get("image")
                if isinstance(service_config, dict)
                else None
            )
            service_matches[service_name] = (
                profile_lookup(image) if isinstance(image, str) and image else None
            )

    for rule in rules:
        rule_id = rule.metadata.id
        is_suppressed = rule_id in disabled
        rule_excluded = excluded.get(rule_id, {})

        for service_name, service_config in services.items():
            try:
                rule_findings = list(
                    rule.check(service_name, service_config, data, lines)
                )
            except Exception as exc:  # noqa: BLE001 - isolate a crashing rule
                report_error(rule_id, service_name, exc)
                continue
            for finding in rule_findings:
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
                match = service_matches.get(service_name)
                if match is not None:
                    finding = enrich_fix(finding, match)
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
