"""CL-0011: Dangerous capabilities added."""

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

CIS_REF = (
    "CIS Docker Benchmark 5.3 — Restrict Linux kernel capabilities within containers"
)

DANGEROUS_CAPS: dict[str, str] = {
    "ALL": (
        "grants every Linux capability — functionally equivalent to disabling "
        "capability-based isolation"
    ),
    "SYS_ADMIN": "near-root access: mount filesystems, configure namespaces, BPF",
    "SYS_PTRACE": "trace/inspect any process, read secrets from memory",
    "NET_ADMIN": "modify routing tables, firewall rules, sniff traffic",
    "SYS_MODULE": "load/unload kernel modules",
    "SYS_RAWIO": "raw I/O port access (iopl/ioperm)",
    "SYS_TIME": "change system clock, affecting all containers and the host",
    "DAC_READ_SEARCH": "bypass file read permission checks on the host",
}

CRITICAL_CAPS: frozenset[str] = frozenset({"ALL"})


@register_rule
class DangerousCapAddRule(BaseRule):
    """Detects services adding dangerous Linux capabilities."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0011",
            name="Dangerous capabilities added",
            description=(
                "Adding powerful Linux capabilities like SYS_ADMIN or SYS_PTRACE "
                "significantly weakens container isolation and can enable container "
                "escapes."
            ),
            severity=Severity.HIGH,
            references=[OWASP_REF, CIS_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        cap_add = service_config.get("cap_add", [])
        if not isinstance(cap_add, list):
            return

        for i, cap in enumerate(cap_add):
            cap_upper = str(cap).upper()
            if cap_upper in DANGEROUS_CAPS:
                severity = (
                    Severity.CRITICAL if cap_upper in CRITICAL_CAPS else Severity.HIGH
                )
                yield Finding(
                    rule_id="CL-0011",
                    severity=severity,
                    service=service_name,
                    message=(
                        f"Service adds dangerous capability {cap_upper}: "
                        f"{DANGEROUS_CAPS[cap_upper]}."
                    ),
                    line=lines.get(f"services.{service_name}.cap_add[{i}]")
                    or lines.get(f"services.{service_name}.cap_add"),
                    fix=(
                        f"Remove {cap_upper} from cap_add. If this capability is "
                        "required, document the justification and consider running "
                        "the workload outside of a container."
                    ),
                    references=[OWASP_REF, CIS_REF],
                )
