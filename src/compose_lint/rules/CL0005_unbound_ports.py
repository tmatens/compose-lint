"""CL-0005: Ports bound to all interfaces."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from compose_lint.fix import is_anchored_or_merged
from compose_lint.models import Finding, RuleMetadata, Severity, TextEdit
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

_CAVEAT = (
    "Binding to 127.0.0.1 drops the port's reachability from other hosts; "
    "intended LAN or remote access breaks — front public exposure with a "
    "reverse proxy and TLS instead."
)

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-5a---be-careful-when-mapping-container-"
    "ports-to-the-host-with-firewalls-like-ufw"
)

CIS_REF = (
    "CIS Docker Benchmark 5.14 — Ensure that incoming container traffic "
    "is bound to a specific host interface"
)

# Matches HOST:CONTAINER (with optional non-bracketed IPv4/hostname prefix)
# or HOST:CONTAINER/proto. Bracketed IPv6 prefixes are stripped before this
# pattern is applied — see _check_short_syntax.
_PORT_PATTERN = re.compile(
    r"^(?:(?P<ip>[^:]+):)?(?P<host>[\d\-]+):(?P<container>[\d\-]+(?:/\w+)?)$"
)

# Values that publish on all interfaces — equivalent to no bind address.
# These are detection patterns, not actual bind addresses.
_WILDCARD_IPS = frozenset({"0.0.0.0", "::", "[::]", "*"})  # nosec B104


def _is_wildcard_ip(value: str) -> bool:
    """Return True if the value publishes on all interfaces."""
    if not value:
        return True
    return value in _WILDCARD_IPS


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

    def fix(
        self,
        finding: Finding,
        data: dict[str, Any],
        lines: dict[str, int],
        text: str,
    ) -> list[TextEdit] | None:
        """Bind a wildcard or unbound published port to ``127.0.0.1``.

        Edits the port scalar in place: prepends ``127.0.0.1:`` when no host IP
        is present, or replaces a wildcard host IP (``0.0.0.0``, ``[::]``, ``*``)
        with ``127.0.0.1``. Only short-syntax string ports are handled. The edit
        carries a caveat because dropping non-local reachability changes network
        behavior (ADR-014).

        Refuses (returns ``None``) for long-syntax mapping entries (adding
        ``host_ip:`` is a different primitive), anchored/merged services, a port
        line that is not a plain block-sequence scalar, and any scalar containing
        ``$`` interpolation (the resolved host is unknown).
        """
        service = finding.service
        services = data.get("services")
        if not isinstance(services, dict):
            return None
        service_config = services.get(service)
        if not isinstance(service_config, dict):
            return None
        if not isinstance(service_config.get("ports"), list):
            return None

        item_line = finding.line
        service_line = lines.get(f"services.{service}")
        if item_line is None or service_line is None:
            return None
        source_lines = text.splitlines(keepends=True)
        n = len(source_lines)
        if not (1 <= item_line <= n and 1 <= service_line <= n):
            return None
        if is_anchored_or_merged(source_lines, service_line):
            return None

        parsed = _scalar_span(source_lines[item_line - 1])
        if parsed is None:
            return None
        scalar, scalar_col = parsed
        if "$" in scalar:
            return None  # variable interpolation: the resolved host is unknown

        span = _host_ip_span(scalar)
        if span is None:
            return None
        repl_start, repl_end, replacement = span
        return [
            TextEdit(
                item_line,
                scalar_col + repl_start,
                item_line,
                scalar_col + repl_end,
                replacement,
                caveat=_CAVEAT,
            )
        ]


def _scalar_span(raw_line: str) -> tuple[str, int] | None:
    """Return ``(scalar, col)`` for a block-sequence entry's scalar value.

    ``col`` is the 1-indexed column where the scalar content begins (inside the
    quote, if any). Strips a surrounding quote and a trailing ``# comment``.
    Returns ``None`` when the line is not a plain ``- value`` entry.
    """
    line = raw_line.rstrip("\n")
    idx = len(line) - len(line.lstrip(" "))
    if idx >= len(line) or line[idx] != "-":
        return None
    idx += 1
    if idx >= len(line) or line[idx] != " ":
        return None  # need whitespace after the dash for a scalar entry
    while idx < len(line) and line[idx] == " ":
        idx += 1
    if idx >= len(line):
        return None

    if line[idx] in ("'", '"'):
        quote = line[idx]
        close = line.find(quote, idx + 1)
        if close == -1:
            return None
        return line[idx + 1 : close], idx + 2  # content starts past the quote
    rest = line[idx:]
    comment = rest.find(" #")
    if comment != -1:
        rest = rest[:comment]
    scalar = rest.rstrip()
    if not scalar:
        return None
    return scalar, idx + 1


def _host_ip_span(scalar: str) -> tuple[int, int, str] | None:
    """Return ``(start, end, replacement)`` for the host-IP edit within ``scalar``.

    A zero-width ``(0, 0, "127.0.0.1:")`` prepends a bind address when none is
    present; ``(0, len, "127.0.0.1")`` replaces a wildcard one. Returns ``None``
    when the scalar is not a short-syntax port or already binds a real interface.
    """
    if scalar.startswith("["):
        bracket = scalar.find("]:")
        if bracket == -1 or not _is_wildcard_ip(scalar[: bracket + 1]):
            return None
        return 0, bracket + 1, "127.0.0.1"
    match = _PORT_PATTERN.match(scalar)
    if not match:
        return None
    ip = match.group("ip")
    if ip is None:
        return 0, 0, "127.0.0.1:"
    if _is_wildcard_ip(ip):
        return 0, len(ip), "127.0.0.1"
    return None  # already bound to a specific interface
