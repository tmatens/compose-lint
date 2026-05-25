"""CL-0005: Ports bound to all interfaces."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from compose_lint.fix import is_anchored_or_merged, line_indent
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
# pattern is applied — see _check_short_syntax. The host and container slots
# also accept a `${VAR}` substitution so a var-valued host port (e.g.
# `${HOSTPORT}:80`) still has its bind-address slot evaluated rather than
# skipping the whole entry (issue #277 F5).
_PORT_PART = r"(?:[\d\-]+(?:/\w+)?|\$\{[^}]+\}(?:/\w+)?)"
_PORT_PATTERN = re.compile(
    rf"^(?:(?P<ip>[^:]+):)?(?P<host>{_PORT_PART}):(?P<container>{_PORT_PART})$"
)

# A bare short-syntax port with no colon (`"3000"`, `3001`, a `"3000-3005"`
# range, optional `/proto`). Docker still publishes it — `docker compose
# config` normalizes `- "3000"` to a `target` with an ephemeral host port
# bound to all interfaces (0.0.0.0) — so it is the same exposure class this
# rule targets (issue #279 R1). Anchored to reject non-port junk.
_BARE_PORT_PATTERN = re.compile(rf"^{_PORT_PART}$")

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
        # A bare port with no colon is still published: Docker assigns an
        # ephemeral host port bound to all interfaces (issue #279 R1). Fire
        # with an ephemeral-port message; reject non-port junk via the pattern.
        if ":" not in port_str:
            if _BARE_PORT_PATTERN.match(port_str):
                yield self._make_finding(
                    port_str, service_name, lines, index, bare=True
                )
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
        bare: bool = False,
    ) -> Finding:
        if bare:
            message = (
                f"Bare port '{port_str}' is published on all interfaces: Docker "
                "assigns a random (ephemeral) host port bound to 0.0.0.0. It "
                "bypasses host firewalls (UFW/firewalld), potentially exposing "
                "this port to the public internet."
            )
            # `127.0.0.1::3000` keeps the ephemeral host port (empty middle
            # field) while pinning the bind address to localhost.
            fix = (
                f"Bind to localhost, keeping an ephemeral host port: "
                f"127.0.0.1::{port_str}\n"
                "If public access is needed, use a reverse proxy with TLS."
            )
        else:
            message = (
                f"Port '{port_str}' is bound to all interfaces. Docker bypasses "
                "host firewalls (UFW/firewalld), potentially exposing this port "
                "to the public internet."
            )
            fix = (
                f"Bind to localhost: 127.0.0.1:{port_str}\n"
                "If public access is needed, use a reverse proxy with TLS."
            )
        return Finding(
            rule_id="CL-0005",
            severity=Severity.HIGH,
            service=service_name,
            message=message,
            line=lines.get(f"services.{service_name}.ports[{index}]")
            or lines.get(f"services.{service_name}.ports"),
            fix=fix,
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

        Short syntax (``- 8080:80``) is edited in the scalar: prepend
        ``127.0.0.1:`` when no host IP is present, or replace a wildcard host IP
        (``0.0.0.0``, ``[::]``, ``*``) with ``127.0.0.1``. Long syntax (a mapping
        with ``published:``) gets a ``host_ip: 127.0.0.1`` key — inserted as a
        sibling when absent, or its wildcard value replaced in place. The edit
        carries a caveat because dropping non-local reachability changes network
        behavior (ADR-014).

        Refuses (returns ``None``) for anchored/merged services, flow-style or
        lone anchor/alias entries, a port line that is not a plain block-sequence
        scalar or mapping, a long-syntax ``host_ip`` whose value is
        empty/null/an alias (ambiguous target), and any scalar or host-IP value
        containing ``$`` interpolation (the resolved host is unknown).
        """
        service = finding.service
        services = data.get("services")
        if not isinstance(services, dict):
            return None
        service_config = services.get(service)
        if not isinstance(service_config, dict):
            return None
        ports = service_config.get("ports")
        if not isinstance(ports, list):
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

        port_config = _port_at_line(ports, lines, service, item_line)
        if isinstance(port_config, dict):
            return _fix_long_syntax(port_config, source_lines, item_line)

        return _fix_short_syntax(source_lines, item_line)


def _port_at_line(
    ports: list[Any],
    lines: dict[str, int],
    service: str,
    item_line: int,
) -> Any:
    """Return the parsed port entry whose sequence line is ``item_line``.

    Matches the finding's line against the recorded ``ports[i]`` line so the
    fixer can tell a long-syntax mapping from a short-syntax scalar without
    re-parsing. Returns ``None`` when no entry maps to that line.
    """
    for index in range(len(ports)):
        if lines.get(f"services.{service}.ports[{index}]") == item_line:
            return ports[index]
    return None


def _fix_short_syntax(source_lines: list[str], item_line: int) -> list[TextEdit] | None:
    """Edit a short-syntax (string) port scalar to bind ``127.0.0.1``."""
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


def _fix_long_syntax(
    port_config: dict[str, Any],
    source_lines: list[str],
    item_line: int,
) -> list[TextEdit] | None:
    """Add or correct ``host_ip`` on a long-syntax port mapping.

    ``item_line`` is the mapping's first-key line (the one carrying the ``-``).
    When ``host_ip`` is absent, insert ``host_ip: 127.0.0.1`` as a sibling key;
    when it holds a non-empty wildcard string, replace that value in place. Any
    other state (empty/null/alias value, flow style, lone anchor) is refused.
    """
    dash = _long_syntax_dash(source_lines[item_line - 1])
    if dash is None:
        return None  # flow style, anchor/alias entry, or a dashless mapping start
    dash_col, key_col = dash

    if "host_ip" not in port_config:
        edit = _insert_host_ip(source_lines, item_line, key_col)
        return [edit] if edit is not None else None

    host_ip = port_config.get("host_ip")
    if isinstance(host_ip, str) and host_ip and _is_wildcard_ip(host_ip):
        edit = _replace_host_ip(source_lines, item_line, dash_col)
        return [edit] if edit is not None else None
    return None  # empty/null/alias host_ip: ambiguous, refuse


def _long_syntax_dash(raw_line: str) -> tuple[int, int] | None:
    """Return ``(dash_col, key_col)`` (0-indexed) for a ``- key: ...`` entry.

    ``dash_col`` is the column of the ``-``; ``key_col`` is the column of the
    first mapping key after it (the indent shared by sibling keys). Returns
    ``None`` for flow style (``- {``/``- [``), a lone anchor/alias (``- &``/
    ``- *``), or any line that is not a block-sequence mapping entry.
    """
    line = raw_line.rstrip("\n")
    dash = len(line) - len(line.lstrip(" "))
    if dash >= len(line) or line[dash] != "-":
        return None
    idx = dash + 1
    if idx >= len(line) or line[idx] != " ":
        return None  # need whitespace after the dash
    while idx < len(line) and line[idx] == " ":
        idx += 1
    if idx >= len(line) or line[idx] in ("{", "[", "&", "*"):
        return None  # flow collection or anchor/alias: not a plain mapping
    return dash, idx


def _insert_host_ip(
    source_lines: list[str],
    item_line: int,
    key_col: int,
) -> TextEdit | None:
    """Return an edit inserting ``host_ip: 127.0.0.1`` as a sibling key.

    The new line is placed right after ``item_line`` at ``key_col`` indentation
    (every long-syntax port field is an inline scalar, so the first line never
    opens a nested block). The file's line ending is preserved; a file whose
    final line has no terminator gets one before the inserted key.
    """
    raw = source_lines[item_line - 1]
    ending = "\r\n" if raw.endswith("\r\n") else "\n"
    new_line = " " * key_col + "host_ip: 127.0.0.1"
    if raw.endswith("\n"):
        return TextEdit(
            item_line + 1, 1, item_line + 1, 1, new_line + ending, caveat=_CAVEAT
        )
    end_col = len(raw) + 1
    return TextEdit(
        item_line, end_col, item_line, end_col, ending + new_line, caveat=_CAVEAT
    )


_HOST_IP_KEY = re.compile(
    r"^[ \t]*(?:-[ \t]+)?host_ip[ \t]*:(?P<sp>[ \t]*)(?P<val>.*)$"
)


def _replace_host_ip(
    source_lines: list[str],
    item_line: int,
    dash_col: int,
) -> TextEdit | None:
    """Return an edit replacing a wildcard ``host_ip`` value with ``127.0.0.1``.

    Scans the mapping's lines (``item_line`` plus every line indented deeper than
    the ``-``) for the ``host_ip:`` key, then replaces its value, keeping any
    surrounding quotes and trailing comment. Returns ``None`` if the key cannot
    be located as a plain wildcard scalar.
    """
    last = item_line
    for idx in range(item_line, len(source_lines)):
        line = source_lines[idx]
        if line.strip() == "":
            continue
        if line_indent(line) > dash_col:
            last = idx + 1
        else:
            break
    for line_no in range(item_line, last + 1):
        edit = _host_ip_value_edit(source_lines[line_no - 1], line_no)
        if edit is not None:
            return edit
    return None


def _host_ip_value_edit(raw_line: str, line_no: int) -> TextEdit | None:
    """Return an edit retargeting a wildcard ``host_ip:`` value on one line.

    Recognises both the dash-bearing first key (``- host_ip: 0.0.0.0``) and a
    sibling (``  host_ip: "::"``). Replaces only the wildcard value — inside the
    quotes when quoted — and leaves indentation, quoting, and any trailing
    comment intact. Returns ``None`` when the line is not a wildcard ``host_ip``.
    """
    line = raw_line.rstrip("\n")
    match = _HOST_IP_KEY.match(line)
    if match is None:
        return None
    val = match.group("val")
    if not val.strip() or "$" in val:
        return None  # empty/null or interpolated: ambiguous target
    val_col = match.start("val") + 1  # 1-indexed column of the value's first char
    if val[0] in ("'", '"'):
        quote = val[0]
        close = val.find(quote, 1)
        if close == -1 or not _is_wildcard_ip(val[1:close]):
            return None
        return TextEdit(
            line_no, val_col + 1, line_no, val_col + close, "127.0.0.1", caveat=_CAVEAT
        )
    token = val.split()[0]
    if not _is_wildcard_ip(token):
        return None
    return TextEdit(
        line_no, val_col, line_no, val_col + len(token), "127.0.0.1", caveat=_CAVEAT
    )


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
