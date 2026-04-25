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
    "label:disable",
}

_PROFILE_DISPLAY_NAME = {
    "seccomp": "seccomp",
    "apparmor": "AppArmor",
    "label": "SELinux",
}

_PROFILE_REMOVAL = {
    "seccomp": "syscall filtering",
    "apparmor": "mandatory access controls",
    "label": "SELinux labeling and confinement",
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
                "Explicitly disabling seccomp, AppArmor, or SELinux removes "
                "syscall filtering, mandatory access controls, and labeling "
                "that limit what a compromised container can do."
            ),
            severity=Severity.HIGH,
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
            if opt_str not in _DISABLED_PROFILES:
                continue
            profile_key = opt_str.split(":", 1)[0]
            profile_name = _PROFILE_DISPLAY_NAME[profile_key]
            removal = _PROFILE_REMOVAL[profile_key]
            yield Finding(
                rule_id="CL-0009",
                severity=Severity.HIGH,
                service=service_name,
                message=(
                    f"Service disables {profile_name} "
                    f"('{opt_str}'). This removes {removal} "
                    "that limit what a compromised container can do."
                ),
                line=lines.get(f"services.{service_name}.security_opt"),
                fix=(
                    f"Remove '{opt_str}' from security_opt. The host applies "
                    f"a default {profile_name} policy automatically."
                ),
                references=[OWASP_REF, CIS_SECCOMP_REF, CIS_APPARMOR_REF],
            )
