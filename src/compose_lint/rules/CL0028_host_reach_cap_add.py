"""CL-0028: Capabilities reaching the host without granting takeover."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._caps import REFERENCES, iter_cap_add

if TYPE_CHECKING:
    from collections.abc import Iterator

# Capabilities whose reach leaves the container and lands on the host with no
# sibling key required, but which stop short of host code execution.
#
# Split out of CL-0027 because they do not share its cell. CL-0027's members
# are conditional on something the image supplies (a different-uid process to
# trace, a file the workload uid cannot already read) and are confined to the
# container; these two are unconditional and host-wide. Pricing one rule on the
# other's members meant setting these aside as "scoping assumptions", which the
# model reserves for reach that depends on a sibling key -- and neither of these
# depends on one. See docs/severity.md and ADR-020.
HOST_REACH_CAPS: dict[str, str] = {
    "PERFMON": (
        "perf_event_open across the whole host — kernel samples and every "
        "process on the machine, a read primitive enabling timing and "
        "side-channel attacks and kernel info disclosure"
    ),
    "SYS_TIME": (
        "set the system clock, which is host-global — Docker does not isolate "
        "CLOCK_REALTIME, so this breaks certificate validation, TOTP, and "
        "Kerberos for every workload on the host"
    ),
}


@register_rule
class HostReachCapAddRule(BaseRule):
    """Detects cap_add entries whose reach extends to the host."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0028",
            name="Host-reaching capability added",
            description=(
                "Adding PERFMON or SYS_TIME reaches past the container to the "
                "host itself — a host-wide kernel read, or the host's clock — "
                "without needing any other key in the file."
            ),
            severity=Severity.HIGH,
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
            service_name, service_config, lines, HOST_REACH_CAPS
        ):
            yield Finding(
                rule_id="CL-0028",
                severity=Severity.HIGH,
                service=service_name,
                evidence=bare,
                message=(f"Service adds {as_written}: {HOST_REACH_CAPS[bare]}."),
                line=line,
                fix=(
                    f"Remove {as_written} from cap_add. If the workload "
                    "genuinely needs it — an NTP client for SYS_TIME, a "
                    "profiler for PERFMON — prefer syncing the clock on the "
                    "host and letting containers inherit it, or profiling from "
                    "the host. Where it is truly required, suppress with a "
                    "reason naming the workload.\n"
                    "Full guide: compose-lint --explain CL-0028"
                ),
                references=REFERENCES,
            )
