"""CL-0005: Ports bound to all interfaces."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-5a---be-careful-when-mapping-container-"
    "ports-to-the-host-with-firewalls-like-ufw"
)

CIS_REF = (
    "CIS Docker Benchmark 5.13"
    " — Bind incoming container traffic to a specific host interface"
)

# Matches short syntax: "HOST:CONTAINER" or "HOST:CONTAINER/proto"
# With optional IP prefix: "IP:HOST:CONTAINER"
# Port ranges: "8000-8100:8000-8100"
_PORT_PATTERN = re.compile(
    r"^(?:(?P<ip>[^:]+):)?(?P<host>[\d\-]+):(?P<container>[\d\-]+(?:/\w+)?)$"
)


def _is_ip_address(value: str) -> bool:
    """Check if a string looks like an IP address."""
    parts = value.split(".")
    if len(parts) == 4:
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    # IPv6 or :: shorthand
    return ":" in value or value == "[::]"


@register_rule
class UnboundPortsRule(BaseRule):
    """Detects port mappings bound to all interfaces."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0005",
            name="Ports bound to all interfaces",
            description=(
                "Docker publishes ports by manipulating iptables directly, "
                "bypassing host firewalls like UFW and firewalld. Ports without "
                "a bind address are accessible on all network interfaces."
            ),
            severity=Severity.HIGH,
            references=[OWASP_REF, CIS_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        ports = service_config.get("ports", [])
        if not isinstance(ports, list):
            return

        for i, port in enumerate(ports):
            if isinstance(port, dict):
                # Long syntax
                yield from self._check_long_syntax(port, service_name, lines, i)
            else:
                # Short syntax
                yield from self._check_short_syntax(str(port), service_name, lines, i)

    def _check_short_syntax(
        self,
        port_str: str,
        service_name: str,
        lines: dict[str, int],
        index: int,
    ) -> Iterator[Finding]:
        # Container-only port (no host mapping) — not published, skip
        if ":" not in port_str:
            return

        match = _PORT_PATTERN.match(port_str)
        if not match:
            return

        ip = match.group("ip")

        # If there's an IP prefix and it looks like an IP, it's bound
        if ip and _is_ip_address(ip):
            return

        # No IP prefix or IP doesn't look like an address — bound to all interfaces
        yield self._make_finding(port_str, service_name, lines, index)

    def _check_long_syntax(
        self,
        port_config: dict[str, Any],
        service_name: str,
        lines: dict[str, int],
        index: int,
    ) -> Iterator[Finding]:
        # Long syntax: target is required, published makes it a host mapping
        if "published" not in port_config:
            return

        host_ip = port_config.get("host_ip", "")
        if host_ip:
            return

        port_desc = f"{port_config.get('published')}:{port_config.get('target')}"
        yield self._make_finding(port_desc, service_name, lines, index)

    def _make_finding(
        self,
        port_str: str,
        service_name: str,
        lines: dict[str, int],
        index: int,
    ) -> Finding:
        return Finding(
            rule_id="CL-0005",
            severity=Severity.HIGH,
            service=service_name,
            message=(
                f"Port '{port_str}' is bound to all interfaces. Docker bypasses "
                "host firewalls (UFW/firewalld), potentially exposing this port "
                "to the public internet."
            ),
            line=lines.get(f"services.{service_name}.ports[{index}]")
            or lines.get(f"services.{service_name}.ports"),
            fix=(
                f"Bind to localhost: 127.0.0.1:{port_str}\n"
                "If public access is needed, use a reverse proxy with TLS."
            ),
            references=[OWASP_REF, CIS_REF],
        )
