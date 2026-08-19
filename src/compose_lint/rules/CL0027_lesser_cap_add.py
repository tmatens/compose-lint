"""CL-0027: Capabilities with a bounded, non-escape grant."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._caps import REFERENCES, iter_cap_add

if TYPE_CHECKING:
    from collections.abc import Iterator

# Capabilities whose grant is real but bounded twice over: it is confined to
# this container, and it converts into impact only where the *image* supplies
# something this file cannot see — a process running as a different uid to
# trace, or a file the workload uid cannot already read. Same-uid tracing and
# same-uid reads need no capability at all.
#
# PERFMON and SYS_TIME were members until the CL-0028 split. They did not
# belong: both reach the host with no sibling key and no help from the image,
# so they sit in a different cell, and keeping them here meant pricing the rule
# on SYS_PTRACE while setting them aside as "scoping assumptions" — a clause
# the model reserves for reach that depends on a sibling key. Splitting these
# two out of CL-0011's HIGH tier is still the precision win the tier exists
# for: a debugger sidecar stops being graded as though it were an escape path.
LESSER_CAPS: dict[str, str] = {
    "SYS_PTRACE": (
        "trace and read the memory of other processes — confined to this "
        "container's own PID namespace unless pid: host is also set"
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
                "Adding SYS_PTRACE or DAC_READ_SEARCH weakens isolation "
                "inside this container without granting an escape, and only "
                "where the image supplies a different-uid process or an "
                "otherwise-unreadable file."
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
                evidence=bare,
                message=(f"Service adds {as_written}: {LESSER_CAPS[bare]}."),
                line=line,
                fix=(
                    f"Remove {as_written} from cap_add unless the workload "
                    "demonstrably needs it (debugger sidecars need "
                    "SYS_PTRACE). Scope a debugger to the container it "
                    'inspects with pid: "service:<name>" rather than '
                    "pid: host. Where it is genuinely required, suppress with "
                    "a reason naming the workload.\n"
                    "Full guide: compose-lint --explain CL-0027"
                ),
                references=REFERENCES,
            )
