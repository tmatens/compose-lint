"""CL-0030: Capabilities that read host state the container cannot otherwise see."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._caps import REFERENCES, iter_cap_add

if TYPE_CHECKING:
    from collections.abc import Iterator

# Capabilities whose reach is a read of host state: no write, no execution, and
# nothing the container can break.
#
# The third rule in the `Direct x Host` cell, and the reason there are three is
# that the cell is CRITICAL until a qualifier names which kind of loss lands.
# CL-0028 takes `integrity-only`, CL-0029 `availability-only`, and this one
# `read-only` -- the model's three kinds of loss, one rule each, because a rule
# carries at most one qualifier. All three ship HIGH, so the split is invisible
# in the severity and visible only in the derivation, which is exactly why the
# member has to be placed by its route rather than by its number.
HOST_DISCLOSURE_CAPS: dict[str, str] = {
    "SYSLOG": (
        "read of the host kernel ring buffer — dmesg is not namespaced, so "
        "the container sees the host's boot and driver log, including kernel "
        "pointers where kptr_restrict allows them"
    ),
}


@register_rule
class HostDisclosureCapAddRule(BaseRule):
    """Detects cap_add entries that read host state from inside a container."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0030",
            name="Host-disclosure capability added",
            description=(
                "Adding SYSLOG lets the container read the host's kernel ring "
                "buffer — host boot, hardware and driver state, and kernel "
                "addresses — without needing any other key in the file."
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
            service_name, service_config, lines, HOST_DISCLOSURE_CAPS
        ):
            yield Finding(
                rule_id="CL-0030",
                severity=Severity.HIGH,
                service=service_name,
                message=(f"Service adds {as_written}: {HOST_DISCLOSURE_CAPS[bare]}."),
                line=line,
                fix=(
                    f"Remove {as_written} from cap_add. A container almost "
                    "never needs the host's kernel log: read it on the host "
                    "with journalctl, or ship it with a log collector that "
                    "runs there. A workload that must see kernel messages "
                    "about its own devices should be given those devices "
                    "explicitly rather than the whole ring buffer, and where "
                    "it is genuinely required, suppress with a reason naming "
                    "the workload.\n"
                    "Full guide: compose-lint --explain CL-0030"
                ),
                references=REFERENCES,
            )
