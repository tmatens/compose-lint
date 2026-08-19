"""CL-0024: Capabilities that grant host code execution."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._caps import REFERENCES, iter_cap_add

if TYPE_CHECKING:
    from collections.abc import Iterator

# Capabilities whose grant is host code execution. Split out of CL-0011 so the
# tier a user must fix first is not averaged in with capabilities that need a
# technique or a co-resident bind mount to matter.
HOST_EXEC_CAPS: dict[str, str] = {
    "ALL": (
        "grants every Linux capability — functionally equivalent to disabling "
        "capability-based isolation, and the capability half of privileged: true"
    ),
    "SYS_ADMIN": (
        "near-root: mount filesystems, configure namespaces, and the historical "
        "home of most container-escape techniques"
    ),
    "SYS_MODULE": (
        "load and unload kernel modules — arbitrary code in kernel space, which "
        "is the host by definition"
    ),
    "SYS_RAWIO": (
        "raw I/O port and /dev/mem-class access — read and write physical memory "
        "and device registers directly"
    ),
}


@register_rule
class HostExecCapAddRule(BaseRule):
    """Detects cap_add entries that hand over host code execution."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0024",
            name="Host-code-execution capability added",
            description=(
                "Adding ALL, SYS_ADMIN, SYS_MODULE, or SYS_RAWIO gives a "
                "container a path to executing code on the host, without "
                "needing a second flaw."
            ),
            severity=Severity.CRITICAL,
            references=REFERENCES,
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        for as_written, bare, line in iter_cap_add(
            service_name, service_config, lines, HOST_EXEC_CAPS
        ):
            yield Finding(
                rule_id="CL-0024",
                severity=Severity.CRITICAL,
                service=service_name,
                evidence=bare,
                message=(
                    f"Service adds {as_written}, which grants host code "
                    f"execution: {HOST_EXEC_CAPS[bare]}."
                ),
                line=line,
                fix=(
                    f"Remove {as_written} from cap_add. There is no "
                    "least-privilege reading of this capability — if the "
                    "workload genuinely needs it, it needs a VM or a host "
                    "process, not a container.\n"
                    "Full guide: compose-lint --explain CL-0024"
                ),
                references=REFERENCES,
            )
