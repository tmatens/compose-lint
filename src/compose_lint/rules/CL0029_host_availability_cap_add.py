"""CL-0029: Capabilities that let a container degrade the host."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._caps import REFERENCES, iter_cap_add

if TYPE_CHECKING:
    from collections.abc import Iterator

# Capabilities whose reach lands on the host but buys the attacker nothing to
# read and nothing to run: the loss is availability, and only availability.
#
# That is the whole reason this is not CL-0028. Both rules sit in the same cell
# -- Direct x Host -- and differ only in the qualifier the model makes them
# pick, because `Direct x Host` is CRITICAL until a qualifier names which of
# the three kinds of loss is actually realised. CL-0028 spends its qualifier on
# `integrity-only` (a clock set, a kernel read). These three spend it on
# `availability-only`. A rule carries at most one qualifier, so one rule cannot
# hold both sets without its derivation becoming false for half its members --
# which is exactly why CL-0028 was split out of CL-0027 (see docs/severity.md).
#
# Each member was measured on Docker 29.4.3 holding only that capability under
# `--cap-drop ALL`, against the same run without it. None needs a sibling key:
# the reach is there with nothing else in the file.
HOST_AVAILABILITY_CAPS: dict[str, str] = {
    "SYS_NICE": (
        "real-time scheduling on the host's CPUs — SCHED_FIFO puts the "
        "container's threads above every ordinary host process, and the "
        "scheduler is not namespaced"
    ),
    "IPC_LOCK": (
        "unbounded memory locking — mlock past RLIMIT_MEMLOCK pins host RAM "
        "that cannot be reclaimed or swapped, and only a memory limit the "
        "file has to set bounds it"
    ),
    "LEASE": (
        "file leases on any host path bind-mounted in — a write lease stalls "
        "the host's own open() of that file for the kernel's lease-break "
        "timeout, and holding it needs only a read-only bind"
    ),
}


@register_rule
class HostAvailabilityCapAddRule(BaseRule):
    """Detects cap_add entries that let a container degrade the host."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0029",
            name="Host-availability capability added",
            description=(
                "Adding SYS_NICE, IPC_LOCK or LEASE lets the container take "
                "host CPU, pin host memory, or stall the host's own file "
                "opens — without needing any other key in the file."
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
            service_name, service_config, lines, HOST_AVAILABILITY_CAPS
        ):
            yield Finding(
                rule_id="CL-0029",
                severity=Severity.HIGH,
                service=service_name,
                evidence=bare,
                message=(f"Service adds {as_written}: {HOST_AVAILABILITY_CAPS[bare]}."),
                line=line,
                fix=(
                    f"Remove {as_written} from cap_add. Workloads that ask for "
                    "these usually have a bounded alternative: set "
                    "`deploy.resources` rather than granting SYS_NICE, and "
                    "size `deploy.resources.limits.memory` rather than "
                    "granting IPC_LOCK — a memory limit also bounds what a "
                    "workload that keeps IPC_LOCK can pin. A storage or "
                    "packet-processing engine that genuinely requires them "
                    "(SPDK and DPDK ask for SYS_NICE and IPC_LOCK together) "
                    "should suppress with a reason naming the workload.\n"
                    "Full guide: compose-lint --explain CL-0029"
                ),
                references=REFERENCES,
            )
