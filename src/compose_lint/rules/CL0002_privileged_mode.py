"""CL-0002: Privileged mode enabled."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-3---do-not-run-containers-with-the---"
    "privileged-flag"
)

CIS_REF = "CIS Docker Benchmark 5.4 — Do not use privileged containers"


@register_rule
class PrivilegedModeRule(BaseRule):
    """Detects services running in privileged mode."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0002",
            name="Privileged mode enabled",
            description=(
                "Privileged mode disables nearly all container isolation. "
                "The container gets all Linux capabilities, access to all host "
                "devices, and can trivially escape to the host."
            ),
            severity=Severity.CRITICAL,
            references=[OWASP_REF, CIS_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        if service_config.get("privileged") is True:
            yield Finding(
                rule_id="CL-0002",
                severity=Severity.CRITICAL,
                service=service_name,
                message=(
                    "Service runs in privileged mode. This disables container "
                    "isolation and is functionally equivalent to running on the "
                    "host as root."
                ),
                line=lines.get(f"services.{service_name}.privileged"),
                fix=(
                    "Remove 'privileged: true' and grant only the specific "
                    "capabilities needed:\n"
                    "  cap_drop:\n"
                    "    - ALL\n"
                    "  cap_add:\n"
                    "    - <SPECIFIC_CAP>"
                ),
                references=[OWASP_REF, CIS_REF],
            )
