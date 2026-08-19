"""CL-0010: Host namespace sharing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-3-limit-capabilities-grant-only-"
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
]

# uts: host and userns_mode: host were removed — both are no-ops under the
# grounded posture (ADR-020), and flagging a directive that changes nothing is
# the CL-0023 failure mode.
#
#   uts: host        — sethostname() needs CAP_SYS_ADMIN, which is not in
#                      Docker's default set, so the container reads the host's
#                      hostname but cannot change it. Verified: the call is
#                      refused even when setting the hostname to its current
#                      value.
#   userns_mode: host — only meaningful against a daemon running with
#                      --userns-remap, and the grounded posture is a daemon at
#                      defaults, where there is no remapping to opt out of.
#                      /proc/self/uid_map is identical with and without it.


@register_rule
class HostNamespaceRule(BaseRule):
    """Detects services sharing host namespaces."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0010",
            name="Host namespace sharing",
            description=(
                "Sharing the host's PID or IPC namespace breaks container "
                "isolation: the container sees and can signal every host "
                "process, or reaches host shared-memory segments."
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
                    evidence=key,
                    message=f"Service shares the host's {desc}",
                    line=lines.get(f"services.{service_name}.{key}"),
                    fix=f"Remove '{key}: {value}' to restore namespace isolation.",
                    references=[OWASP_REF, cis_ref],
                )
