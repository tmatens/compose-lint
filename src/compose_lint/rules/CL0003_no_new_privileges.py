"""CL-0003: Privilege escalation not blocked."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-4---add-no-new-privileges-flag"
)

CIS_REF = (
    "CIS Docker Benchmark 5.25"
    " — Restrict container from acquiring additional privileges"
)


@register_rule
class NoNewPrivilegesRule(BaseRule):
    """Detects services missing no-new-privileges security option."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0003",
            name="Privilege escalation not blocked",
            description=(
                "Without no-new-privileges, processes inside the container can "
                "gain additional privileges via setuid/setgid binaries. An "
                "attacker who gains shell access could escalate to root."
            ),
            severity=Severity.WARNING,
            references=[OWASP_REF, CIS_REF],
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
            security_opt = []

        has_no_new_privs = any(
            str(opt).strip() in ("no-new-privileges:true", "no-new-privileges")
            for opt in security_opt
        )

        if not has_no_new_privs:
            yield Finding(
                rule_id="CL-0003",
                severity=Severity.WARNING,
                service=service_name,
                message=(
                    "Service does not set no-new-privileges. Processes inside "
                    "the container can escalate privileges via setuid/setgid binaries."
                ),
                line=lines.get(f"services.{service_name}"),
                fix=(
                    "Add to your service:\n"
                    "  security_opt:\n"
                    "    - no-new-privileges:true"
                ),
                references=[OWASP_REF, CIS_REF],
            )
