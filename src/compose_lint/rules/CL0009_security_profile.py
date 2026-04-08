"""CL-0009: Security profile disabled."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-6---use-linux-security-module-"
    "seccomp-apparmor-or-selinux"
)

CIS_SECCOMP_REF = "CIS Docker Benchmark 5.21 — Do not disable default seccomp profile"
CIS_APPARMOR_REF = (
    "CIS Docker Benchmark 5.2 — Verify SELinux/AppArmor profile is enabled"
)

_DISABLED_PROFILES = {
    "seccomp:unconfined",
    "apparmor:unconfined",
}


@register_rule
class SecurityProfileRule(BaseRule):
    """Detects services with disabled security profiles."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0009",
            name="Security profile disabled",
            description=(
                "Explicitly disabling seccomp or AppArmor removes syscall "
                "filtering and mandatory access controls that limit what a "
                "compromised container can do."
            ),
            severity=Severity.WARNING,
            references=[OWASP_REF, CIS_SECCOMP_REF, CIS_APPARMOR_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        security_opt = service_config.get("security_opt", [])
        if not isinstance(security_opt, list):
            return

        for opt in security_opt:
            opt_str = str(opt).strip().lower()
            if opt_str in _DISABLED_PROFILES:
                profile_type = opt_str.split(":")[0]
                removal = (
                    "syscall filtering"
                    if profile_type == "seccomp"
                    else "mandatory access controls"
                )
                yield Finding(
                    rule_id="CL-0009",
                    severity=Severity.WARNING,
                    service=service_name,
                    message=(
                        f"Service disables {profile_type} profile "
                        f"('{opt_str}'). This removes {removal} "
                        "that limit what a compromised container can do."
                    ),
                    line=lines.get(f"services.{service_name}.security_opt"),
                    fix=(
                        f"Remove '{opt_str}' from security_opt. Docker applies "
                        f"a default {profile_type} profile automatically."
                    ),
                    references=[OWASP_REF, CIS_SECCOMP_REF, CIS_APPARMOR_REF],
                )
