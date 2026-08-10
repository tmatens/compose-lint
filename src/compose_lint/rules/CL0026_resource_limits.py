"""CL-0026: No resource limits (memory / CPU)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html"
    "#rule-7-limit-resources-memory-cpu-file-descriptors-processes-restarts"
)

CIS_MEM_REF = (
    "CIS Docker Benchmark 5.10 — Ensure that the memory usage for containers is limited"
)
CIS_CPU_REF = (
    "CIS Docker Benchmark 5.11 — Ensure that CPU priority is set "
    "appropriately on containers"
)

REFERENCES = [OWASP_REF, CIS_MEM_REF, CIS_CPU_REF]


def _deploy_limits(service_config: dict[str, Any]) -> dict[str, Any]:
    """``deploy.resources.limits`` if it is a mapping, else empty."""
    deploy = service_config.get("deploy")
    if not isinstance(deploy, dict):
        return {}
    resources = deploy.get("resources")
    if not isinstance(resources, dict):
        return {}
    limits = resources.get("limits")
    return limits if isinstance(limits, dict) else {}


def _is_set(value: Any) -> bool:
    """A limit counts only if it carries a value.

    ``mem_limit:`` with nothing after it parses to ``None``, and an empty
    string is not a limit either — both would otherwise read as "declared".
    """
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return True


@register_rule
class ResourceLimitsRule(BaseRule):
    """Detects services that bound neither memory nor CPU.

    Both are unbounded by default — a container's ``memory.max`` is ``max`` and
    its ``cpu.max`` is ``max 100000`` unless a limit is set (``_cl0026`` in
    ``scripts/validate_rule_premises.py`` re-proves this on every CI run). So a
    single compromised or runaway service can exhaust the host's memory or its
    CPU, which is the difference between one degraded container and a degraded
    host.
    """

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0026",
            name="No resource limits",
            description=(
                "A service with no memory or CPU limit can exhaust the host's "
                "resources, degrading every other container on it."
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
        limits = _deploy_limits(service_config)

        has_memory = _is_set(service_config.get("mem_limit")) or _is_set(
            limits.get("memory")
        )
        # ``cpu_quota`` bounds CPU as surely as ``cpus`` does — it writes the
        # quota half of the same ``cpu.max`` — so a service using the older
        # spelling is honouring the control and is not flagged.
        has_cpu = (
            _is_set(service_config.get("cpus"))
            or _is_set(service_config.get("cpu_quota"))
            or _is_set(limits.get("cpus"))
        )
        if has_memory and has_cpu:
            return

        if not has_memory and not has_cpu:
            missing = "no memory limit and no CPU limit"
        elif not has_memory:
            missing = "no memory limit"
        else:
            missing = "no CPU limit"

        yield Finding(
            rule_id="CL-0026",
            severity=Severity.MEDIUM,
            service=service_name,
            message=(
                f"Service declares {missing}. Docker imposes neither by "
                "default, so the container can consume the host's memory or "
                "CPU until other workloads are starved."
            ),
            line=lines.get(f"services.{service_name}"),
            fix=(
                "Bound both, sized from the workload's observed steady state:\n"
                "  deploy:\n"
                "    resources:\n"
                "      limits:\n"
                "        memory: 512M\n"
                "        cpus: '0.50'\n"
                "Compose v2 honours deploy.resources.limits outside Swarm.\n"
                "The v2 spellings mem_limit: 512m and cpus: 0.50 also work.\n"
                "Reservations are not limits: mem_reservation and\n"
                "cpu_shares express priority under contention and leave the\n"
                "hard ceiling unbounded.\n"
                "Full guide: compose-lint --explain CL-0026"
            ),
            references=REFERENCES,
        )
