"""CL-0015: Healthcheck explicitly disabled."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

CIS_REF_46 = (
    "CIS Docker Benchmark 4.6 — Add HEALTHCHECK instruction to container images"
)
CIS_REF_527 = (
    "CIS Docker Benchmark 5.27 — Ensure container health is checked at runtime"
)


@register_rule
class HealthcheckDisabledRule(BaseRule):
    """Detects services with healthcheck explicitly disabled."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0015",
            name="Healthcheck disabled",
            description=(
                "Explicitly disabling the healthcheck removes runtime health "
                "monitoring. Orchestrators cannot detect or restart unhealthy "
                "containers."
            ),
            severity=Severity.LOW,
            references=[CIS_REF_46, CIS_REF_527],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        healthcheck = service_config.get("healthcheck")
        if not isinstance(healthcheck, dict):
            return

        disable = healthcheck.get("disable")
        test = healthcheck.get("test")
        disabled_via_test = test == ["NONE"] or test == "NONE"

        if disable is True or disabled_via_test:
            offending = "disable: true" if disable is True else 'test: ["NONE"]'
            yield Finding(
                rule_id="CL-0015",
                severity=Severity.LOW,
                service=service_name,
                message=(
                    f"Healthcheck is explicitly disabled via {offending}. The "
                    "orchestrator cannot detect or automatically restart "
                    "unhealthy containers."
                ),
                line=lines.get(f"services.{service_name}.healthcheck"),
                fix=(
                    f"Remove '{offending}' and configure a healthcheck:\n"
                    "  healthcheck:\n"
                    '    test: ["CMD", "curl", "-f", "http://localhost/"]\n'
                    "    interval: 30s\n"
                    "    timeout: 10s\n"
                    "    retries: 3"
                ),
                references=[CIS_REF_46, CIS_REF_527],
            )
