"""CL-0026: No resource limits (memory / CPU)."""

from __future__ import annotations

import re
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


_INTERPOLATION_DEFAULT_RE = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=]([^}]*)\}$")


def _interpolation_default(text: str) -> str | None:
    """Return the fallback in ``${VAR:-512m}``/``${VAR:=0}``, if there is one.

    A bare ``${VAR}`` is genuinely unknowable and stays a limit. A *defaulted*
    interpolation is not: the value the file ships with is written in the file.
    ``${MEM:-0}`` is the likeliest way a parameterised stack ends up unbounded —
    the operator simply never sets the variable — and treating the whole family
    as unknowable let it through.
    """
    match = _INTERPOLATION_DEFAULT_RE.match(text)
    return match.group(1).strip() if match else None


def _is_set(value: Any) -> bool:
    """Whether a limit key actually bounds anything.

    Being *present* is not enough. ``mem_limit:`` with nothing after it parses
    to ``None``, and an empty string is not a limit either. More subtly, Docker
    reads a non-positive limit as **unlimited** — ``--memory 0`` and ``--cpus 0``
    impose no cap at all — so ``mem_limit: 0`` is an unbounded container wearing
    the syntax of a bounded one, and must still fire. That is the same
    non-positive-means-disabled convention CL-0012 used to flag for pids.
    """
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return value > 0
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return False
        default = _interpolation_default(text)
        if default is not None:
            # "${MEM:-0}" — the fallback is written right here, so it is not
            # unknowable. Judge the value the file actually ships with.
            return _is_set(default)
        # "512M", "1.5", "0", "0m" — a size/quantity with an optional unit
        # suffix. If the numeric part is non-positive it bounds nothing.
        number = text.rstrip("bBkKmMgG")
        try:
            return float(number) > 0
        except ValueError:
            # A bare interpolation such as "${MEM_LIMIT}". Treat it as a limit:
            # the value is unknowable from the file, and assuming the worst
            # would fire on every parameterised compose file. Anything else is
            # not a quantity Docker accepts, so it bounds nothing.
            return "$" in text
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
