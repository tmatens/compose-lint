"""CL-0011: Strong host-adjacent capabilities added."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._caps import REFERENCES, iter_cap_add

if TYPE_CHECKING:
    from collections.abc import Iterator

# Capabilities that reach past this container without handing over host code
# execution outright. Each needs a published technique or a second defect to
# become an escape, which is what separates this tier from CL-0024's.
#
# MKNOD, SYS_CHROOT and DAC_OVERRIDE are deliberately absent: all three are in
# Docker's default set, so flagging them on cap_add scored the *declaration*
# rather than the runtime state and inverted the gate — cap_drop: [ALL] plus
# cap_add: [DAC_OVERRIDE] failed while no cap_drop at all passed (issue #492).
STRONG_CAPS: dict[str, str] = {
    "NET_ADMIN": (
        "reconfigure interfaces, routes and firewall rules — enables "
        "transparent interception of other containers' traffic, which NET_RAW "
        "alone cannot reach"
    ),
    "BPF": (
        "load BPF programs — kernel introspection and manipulation, and a "
        "recurring container-escape surface"
    ),
    "SYS_BOOT": (
        "reboot or power off the host via reboot(2) — host availability. It "
        "does not load a kernel: kexec_load is blocked by the default seccomp "
        "profile even with this capability held"
    ),
}


@register_rule
class DangerousCapAddRule(BaseRule):
    """Detects cap_add entries that reach past the container."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0011",
            name="Strong host-adjacent capability added",
            description=(
                "Adding NET_ADMIN, BPF, or SYS_BOOT reaches past the "
                "container — cross-container traffic interception, kernel "
                "manipulation, or host availability — though each needs a "
                "technique or a second flaw to become an escape."
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
            service_name, service_config, lines, STRONG_CAPS
        ):
            yield Finding(
                rule_id="CL-0011",
                severity=Severity.HIGH,
                service=service_name,
                message=(f"Service adds {as_written}: {STRONG_CAPS[bare]}."),
                line=line,
                fix=(
                    f"Remove {as_written} from cap_add. VPN and networking "
                    "containers legitimately need NET_ADMIN — where that is "
                    "the case, suppress with a reason naming the workload "
                    "rather than leaving it unexplained.\n"
                    "Full guide: compose-lint --explain CL-0011"
                ),
                references=REFERENCES,
            )
