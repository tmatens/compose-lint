"""CL-0006: No capability restrictions."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-3---limit-capabilities-grant-only-"
    "specific-capabilities-needed-by-a-container"
)

CIS_REF = "CIS Docker Benchmark 5.3 — Restrict Linux kernel capabilities"


@register_rule
class CapDropRule(BaseRule):
    """Detects services that do not drop Linux capabilities."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0006",
            name="No capability restrictions",
            description=(
                "Containers retain ~14 default Linux capabilities unless explicitly "
                "dropped. These include NET_RAW (ARP spoofing), SYS_CHROOT, and "
                "MKNOD, which are unnecessary for most workloads."
            ),
            severity=Severity.ERROR,
            references=[OWASP_REF, CIS_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        cap_drop = service_config.get("cap_drop", [])
        if not isinstance(cap_drop, list):
            cap_drop = []

        # Normalize to uppercase for comparison
        dropped = {str(cap).upper() for cap in cap_drop}

        if "ALL" not in dropped:
            yield Finding(
                rule_id="CL-0006",
                severity=Severity.ERROR,
                service=service_name,
                message=(
                    "Service does not drop all capabilities. Containers retain "
                    "~14 default capabilities including NET_RAW, SYS_CHROOT, "
                    "and MKNOD."
                ),
                line=lines.get(f"services.{service_name}"),
                fix=(
                    "Drop all capabilities and add back only what is needed:\n"
                    "  cap_drop:\n"
                    "    - ALL\n"
                    "  cap_add:\n"
                    "    - <SPECIFIC_CAP>"
                ),
                references=[OWASP_REF, CIS_REF],
            )
