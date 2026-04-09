"""CL-0007: Filesystem not read-only."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-8---set-filesystem-and-volumes-to-read-only"
)

CIS_REF = "CIS Docker Benchmark 5.12 — Mount container's root filesystem as read only"


@register_rule
class ReadOnlyFilesystemRule(BaseRule):
    """Detects services without a read-only root filesystem."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0007",
            name="Filesystem not read-only",
            description=(
                "A writable root filesystem allows attackers to modify binaries, "
                "install backdoors, or persist malware inside the container."
            ),
            severity=Severity.MEDIUM,
            references=[OWASP_REF, CIS_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        if service_config.get("read_only") is not True:
            yield Finding(
                rule_id="CL-0007",
                severity=Severity.MEDIUM,
                service=service_name,
                message=(
                    "Service root filesystem is writable. An attacker can modify "
                    "binaries, install tools, or persist malware inside the container."
                ),
                line=lines.get(f"services.{service_name}"),
                fix=(
                    "Set the root filesystem to read-only and use tmpfs for "
                    "writable paths:\n"
                    "  read_only: true\n"
                    "  tmpfs:\n"
                    "    - /tmp\n"
                    "    - /run"
                ),
                references=[OWASP_REF, CIS_REF],
            )
