"""CL-0027: Capabilities with a bounded, non-escape grant."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._caps import REFERENCES, iter_cap_add

if TYPE_CHECKING:
    from collections.abc import Iterator

# Capabilities worth flagging, but whose grant is bounded: an intra-container
# primitive, a kernel *read*, a host-integrity effect short of takeover, or a
# host read that needs a bind mount another rule already flags. Splitting these
# out of CL-0011's HIGH tier is a precision win: the legitimate workloads that
# need them (an NTP client, a debugger sidecar, a profiler) stop being graded
# as though they were escape paths.
LESSER_CAPS: dict[str, str] = {
    "SYS_PTRACE": (
        "trace and read the memory of other processes — confined to this "
        "container's own PID namespace unless pid: host is also set"
    ),
    "PERFMON": (
        "perf_event_open — a kernel read primitive enabling timing and "
        "side-channel attacks and kernel info disclosure"
    ),
    "SYS_TIME": (
        "set the system clock, which is host-global — Docker does not isolate "
        "CLOCK_REALTIME, so this breaks certificate validation, TOTP, and "
        "Kerberos for every workload on the host"
    ),
    "DAC_READ_SEARCH": (
        "bypass file-read permission checks, and read host files via "
        "open_by_handle_at — but only where a host bind mount is already "
        "present, which is flagged separately"
    ),
}


@register_rule
class LesserCapAddRule(BaseRule):
    """Detects cap_add entries with a bounded grant."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0027",
            name="Bounded-grant capability added",
            description=(
                "Adding SYS_PTRACE, PERFMON, SYS_TIME, or DAC_READ_SEARCH "
                "weakens isolation without granting an escape: an "
                "intra-container primitive, a kernel read, or a host-integrity "
                "effect short of takeover."
            ),
            severity=Severity.MEDIUM,
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
            service_name, service_config, lines, LESSER_CAPS
        ):
            yield Finding(
                rule_id="CL-0027",
                severity=Severity.MEDIUM,
                service=service_name,
                message=(f"Service adds {as_written}: {LESSER_CAPS[bare]}."),
                line=line,
                fix=(
                    f"Remove {as_written} from cap_add unless the workload "
                    "demonstrably needs it (NTP clients need SYS_TIME, "
                    "debugger and profiler sidecars need SYS_PTRACE or "
                    "PERFMON). Where it is genuinely required, suppress with "
                    "a reason naming the workload.\n"
                    "Full guide: compose-lint --explain CL-0027"
                ),
                references=REFERENCES,
            )
