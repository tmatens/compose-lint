"""CL-0023: Dangerous network sysctl enabled."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

DOCKER_REF = "https://docs.docker.com/reference/compose-file/services/#sysctls"

CIS_REF = (
    "CIS Distribution Independent Linux Benchmark §3.3 — Network Parameters "
    "(Host and Router)"
)

# Namespaced net.* sysctls whose secure posture is "off" (kernel default 0).
# Enabling one inside a container re-enables routing/redirect behavior that turns
# the container into a network pivot — most acutely when it also shares the host
# network namespace (CL-0008) or bridges multiple Docker networks.
_DANGEROUS_SYSCTLS: dict[str, str] = {
    "net.ipv4.ip_forward": (
        "enables IPv4 forwarding — the container can route traffic between "
        "networks, a pivot primitive"
    ),
    "net.ipv6.conf.all.forwarding": (
        "enables IPv6 forwarding — the container can route traffic between "
        "networks, a pivot primitive"
    ),
    "net.ipv4.conf.all.accept_source_route": (
        "accepts source-routed packets — lets an attacker dictate the return "
        "path and bypass routing controls"
    ),
    "net.ipv4.conf.all.accept_redirects": (
        "accepts ICMP redirects — an attacker can rewrite the container's routing table"
    ),
    "net.ipv4.conf.all.send_redirects": (
        "sends ICMP redirects — can be abused to reroute other hosts' traffic"
    ),
}


def _enabled(value: Any) -> bool:
    """Return whether a sysctl value turns the parameter on (``1``/``true``)."""
    if isinstance(value, bool):
        return value
    return str(value).strip() == "1"


def _entries(sysctls: Any) -> list[tuple[str, Any, str]]:
    """Normalize the map and list ``sysctls`` forms to ``(key, value, suffix)``.

    ``suffix`` is the line-map marker for the entry: ``.<key>`` for the map form
    and ``[i]`` for the list form. Both are looked up against the block line as a
    fallback, so a miss (e.g. a flow-style block) still yields a usable line.
    """
    if isinstance(sysctls, dict):
        return [(str(key), value, f".{key}") for key, value in sysctls.items()]
    if isinstance(sysctls, list):
        out: list[tuple[str, Any, str]] = []
        for i, entry in enumerate(sysctls):
            if isinstance(entry, str) and "=" in entry:
                key, _, value = entry.partition("=")
                out.append((key.strip(), value.strip(), f"[{i}]"))
        return out
    return []


@register_rule
class DangerousSysctlsRule(BaseRule):
    """Detects services enabling escape-adjacent network sysctls."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0023",
            name="Dangerous network sysctl enabled",
            description=(
                "Enabling a forwarding or redirect net.* sysctl inside a "
                "container re-enables routing behavior the kernel disables by "
                "default, turning the container into a network pivot."
            ),
            severity=Severity.MEDIUM,
            references=[DOCKER_REF, CIS_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        for key, value, suffix in _entries(service_config.get("sysctls")):
            if key not in _DANGEROUS_SYSCTLS or not _enabled(value):
                continue
            line = lines.get(f"services.{service_name}.sysctls{suffix}") or lines.get(
                f"services.{service_name}.sysctls"
            )
            yield Finding(
                rule_id="CL-0023",
                severity=Severity.MEDIUM,
                service=service_name,
                message=(
                    f"Service enables sysctl '{key}': "
                    f"{_DANGEROUS_SYSCTLS[key]}. The risk is acute when the "
                    "container shares the host network (CL-0008) or bridges "
                    "multiple networks."
                ),
                line=line,
                fix=(
                    f"Remove '{key}' or set it to 0 unless the workload must "
                    "route traffic. If routing is required, keep the container "
                    "off the host network and limit it to the networks it serves."
                ),
                references=[DOCKER_REF, CIS_REF],
            )
