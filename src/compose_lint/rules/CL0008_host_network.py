"""CL-0008: Host network mode."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-5---be-mindful-of-inter-container-connectivity"
)

CIS_REF = "CIS Docker Benchmark 5.9 — Do not share the host's network namespace"


@register_rule
class HostNetworkRule(BaseRule):
    """Detects services using host network mode."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0008",
            name="Host network mode",
            description=(
                "Host network mode disables network isolation entirely. The "
                "container shares the host's IP address, can bind any port, and "
                "can observe all host network traffic."
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
        network_mode = service_config.get("network_mode", "")
        if str(network_mode) == "host":
            yield Finding(
                rule_id="CL-0008",
                severity=Severity.ERROR,
                service=service_name,
                message=(
                    "Service uses host network mode. This disables network "
                    "isolation — the container shares the host's network stack "
                    "and can bind any port or sniff traffic."
                ),
                line=lines.get(f"services.{service_name}.network_mode"),
                fix=(
                    "Remove 'network_mode: host' and use bridge networking with "
                    "explicit port mappings:\n"
                    "  ports:\n"
                    '    - "127.0.0.1:8080:8080"'
                ),
                references=[OWASP_REF, CIS_REF],
            )
