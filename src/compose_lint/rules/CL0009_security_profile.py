"""CL-0009: Security profile disabled."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.fix import (
    block_span,
    delete_lines,
    is_anchored_or_merged,
    opens_block_body,
)
from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

    from compose_lint.models import TextEdit

_CAVEAT = (
    "Removing the unconfined entry re-applies the default seccomp/AppArmor "
    "profile; a workload that relies on a syscall the default profile blocks "
    "may fail."
)

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-6---use-linux-security-module-"
    "seccomp-apparmor-or-selinux"
)

CIS_SECCOMP_REF = "CIS Docker Benchmark 5.21 — Do not disable default seccomp profile"
CIS_APPARMOR_REF = (
    "CIS Docker Benchmark 5.1 — Ensure that, if applicable, an AppArmor profile "
    "is enabled"
)
CIS_SELINUX_REF = (
    "CIS Docker Benchmark 5.2 — Ensure that, if applicable, SELinux security "
    "options are set"
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
            references=[OWASP_REF, CIS_SECCOMP_REF, CIS_APPARMOR_REF, CIS_SELINUX_REF],
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

        for i, opt in enumerate(security_opt):
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
                line=lines.get(f"services.{service_name}.security_opt[{i}]")
                or lines.get(f"services.{service_name}.security_opt"),
                fix=(
                    f"Remove '{opt_str}' from security_opt. The host applies "
                    f"a default {profile_name} policy automatically."
                ),
                references=[
                    OWASP_REF,
                    CIS_SECCOMP_REF,
                    CIS_APPARMOR_REF,
                    CIS_SELINUX_REF,
                ],
            )

    def fix(
        self,
        finding: Finding,
        data: dict[str, Any],
        lines: dict[str, int],
        text: str,
    ) -> list[TextEdit] | None:
        """Delete the unconfined ``security_opt`` entry the finding flags.

        Removes just the offending list item when a legitimate entry remains,
        or drops the whole ``security_opt:`` block when the offending entry is
        the sole one (never leaving ``security_opt:`` empty). Refuses (returns
        ``None``) for anchored/merged services, flow-style lists, and the
        ambiguous case where every entry is offending but more than one exists —
        collapsing that correctly would need the per-finding fixers to
        coordinate, which they can't (ADR-014 refusal policy). The edit carries
        a caveat because re-applying the default profile changes runtime
        behavior.
        """
        service = finding.service
        services = data.get("services")
        if not isinstance(services, dict):
            return None
        service_config = services.get(service)
        if not isinstance(service_config, dict):
            return None
        security_opt = service_config.get("security_opt")
        if not isinstance(security_opt, list) or not security_opt:
            return None

        item_line = finding.line
        so_line = lines.get(f"services.{service}.security_opt")
        service_line = lines.get(f"services.{service}")
        if item_line is None or so_line is None or service_line is None:
            return None

        source_lines = text.splitlines(keepends=True)
        n = len(source_lines)
        if not (1 <= service_line <= n and 1 <= so_line <= n and 1 <= item_line <= n):
            return None

        if is_anchored_or_merged(source_lines, service_line):
            return None
        if not opens_block_body(source_lines[so_line - 1]):
            return None

        disabled = sum(
            1 for opt in security_opt if str(opt).strip().lower() in _DISABLED_PROFILES
        )
        legit_remaining = len(security_opt) - disabled

        if legit_remaining >= 1:
            # A legitimate entry survives, so the list stays non-empty: remove
            # only this item's line.
            if not source_lines[item_line - 1].lstrip().startswith("- "):
                return None
            return [delete_lines(source_lines, item_line, item_line, caveat=_CAVEAT)]
        if len(security_opt) == 1:
            # Sole entry is the offending one: drop the whole block.
            first, last = block_span(source_lines, so_line)
            return [delete_lines(source_lines, first, last, caveat=_CAVEAT)]
        return None
