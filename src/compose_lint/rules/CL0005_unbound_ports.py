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

# Matches HOST:CONTAINER (with optional non-bracketed IPv4/hostname prefix)
# or HOST:CONTAINER/proto. Bracketed IPv6 prefixes are stripped before this
# pattern is applied — see _check_short_syntax.
_PORT_PATTERN = re.compile(
    r"^(?:(?P<ip>[^:]+):)?(?P<host>[\d\-]+):(?P<container>[\d\-]+(?:/\w+)?)$"
)

# Values that publish on all interfaces — equivalent to no bind address.
_WILDCARD_IPS = frozenset({"0.0.0.0", "::", "[::]", "*"})


def _is_wildcard_ip(value: str) -> bool:
    """Return True if the value publishes on all interfaces."""
    if not value:
        return True
    if value in _WILDCARD_IPS:
        return True
    # Bracketed IPv6 form like "[::]" — already covered above, but also
    # accept "[0.0.0.0]" defensively.
    if value.startswith("[") and value.endswith("]"):
        return value[1:-1] in {"::", "0.0.0.0", "*"}
    return False


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
                "a bind address — or bound to a wildcard like 0.0.0.0 or :: — "
                "are accessible on all network interfaces."
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
                yield from self._check_long_syntax(port, service_name, lines, i)
            else:
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

        # Extract bracketed IPv6 prefix (e.g. "[::]:8080:80") before the
        # main regex, which doesn't accept colons inside the IP group.
        ip: str | None = None
        rest = port_str
        if port_str.startswith("["):
            end = port_str.find("]:")
            if end == -1:
                return  # malformed
            ip = port_str[: end + 1]
            rest = port_str[end + 2 :]

        match = _PORT_PATTERN.match(rest)
        if not match:
            return

        if ip is None:
            ip = match.group("ip")

        # Fire when there's no bind address or it's a wildcard form.
        # Any other value (loopback, specific interface IP, hostname) is
        # treated as a real bind.
        if ip is None or _is_wildcard_ip(ip):
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
        if isinstance(host_ip, str) and not _is_wildcard_ip(host_ip):
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
