"""CL-0012: PIDs cgroup limit disabled."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

CIS_REF = "CIS Docker Benchmark 5.29 — Ensure the PIDs cgroup limit is set"


@register_rule
class PidsLimitRule(BaseRule):
    """Detects services with PIDs cgroup limit explicitly disabled."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0012",
            name="PIDs cgroup limit disabled",
            description=(
                "Setting pids_limit to 0 or -1 removes the process count limit, "
                "allowing a container to fork-bomb the host."
            ),
            severity=Severity.MEDIUM,
            references=[CIS_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        pids_limit = service_config.get("pids_limit")
        if pids_limit is None:
            return

        try:
            value = int(pids_limit)
        except (TypeError, ValueError):
            return

        if value <= 0:
            yield Finding(
                rule_id="CL-0012",
                severity=Severity.MEDIUM,
                service=service_name,
                message=(
                    f"PIDs cgroup limit is disabled (pids_limit: {value}). "
                    "The container can create unlimited processes, enabling "
                    "fork bomb attacks against the host."
                ),
                line=lines.get(f"services.{service_name}.pids_limit"),
                fix=(
                    "Set a positive pids_limit appropriate for your workload:\n"
                    "  pids_limit: 200"
                ),
                references=[CIS_REF],
            )
