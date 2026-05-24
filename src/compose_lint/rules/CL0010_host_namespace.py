"""CL-0010: Host namespace sharing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-3---limit-capabilities-grant-only-"
    "specific-capabilities-needed-by-a-container"
)

_NAMESPACE_CHECKS: list[tuple[str, str, str, str]] = [
    (
        "pid",
        "host",
        (
            "CIS Docker Benchmark 5.16 — Ensure that the host's process "
            "namespace is not shared"
        ),
        "process namespace. The container can see and signal all host processes.",
    ),
    (
        "ipc",
        "host",
        (
            "CIS Docker Benchmark 5.17 — Ensure that the host's IPC "
            "namespace is not shared"
        ),
        "IPC namespace. The container can access host shared memory segments.",
    ),
    (
        "userns_mode",
        "host",
        (
            "CIS Docker Benchmark 5.31 — Ensure that the host's user "
            "namespaces are not shared"
        ),
        "user namespace. UID/GID mapping between container and host is disabled.",
    ),
    (
        "uts",
        "host",
        (
            "CIS Docker Benchmark 5.21 — Ensure that the host's UTS "
            "namespace is not shared"
        ),
        "UTS namespace. The container can change the host's hostname.",
    ),
]


@register_rule
class HostNamespaceRule(BaseRule):
    """Detects services sharing host namespaces."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0010",
            name="Host namespace sharing",
            description=(
                "Sharing host namespaces (PID, IPC, user, UTS) breaks container "
                "isolation. The container gains visibility into or control over "
                "host-level resources."
            ),
            severity=Severity.HIGH,
            references=[
                OWASP_REF,
                "CIS Docker Benchmark 5.16, 5.17, 5.21, 5.31",
            ],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        for key, value, cis_ref, desc in _NAMESPACE_CHECKS:
            if str(service_config.get(key, "")).lower() == value:
                yield Finding(
                    rule_id="CL-0010",
                    severity=Severity.HIGH,
                    service=service_name,
                    message=f"Service shares the host's {desc}",
                    line=lines.get(f"services.{service_name}.{key}"),
                    fix=f"Remove '{key}: {value}' to restore namespace isolation.",
                    references=[OWASP_REF, cis_ref],
                )
