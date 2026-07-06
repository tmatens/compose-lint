"""CL-0015: Healthcheck explicitly disabled."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint._yaml_edit import (
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
    "Re-enabling the healthcheck restores the image's default check; an "
    "unhealthy status can affect depends_on conditions and orchestration."
)

CIS_REF_46 = (
    "CIS Docker Benchmark 4.6 — Ensure that HEALTHCHECK instructions have "
    "been added to container images"
)
CIS_REF_527 = (
    "CIS Docker Benchmark 5.27 — Ensure that container health is checked at runtime"
)


@register_rule
class HealthcheckDisabledRule(BaseRule):
    """Detects services with healthcheck explicitly disabled."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0015",
            name="Healthcheck disabled",
            description=(
                "Explicitly disabling the healthcheck removes runtime health "
                "monitoring. Orchestrators cannot detect or restart unhealthy "
                "containers."
            ),
            severity=Severity.LOW,
            references=[CIS_REF_46, CIS_REF_527],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        healthcheck = service_config.get("healthcheck")
        if not isinstance(healthcheck, dict):
            return

        disable = healthcheck.get("disable")
        test = healthcheck.get("test")
        disabled_via_test = test == ["NONE"] or test == "NONE"

        if disable is True or disabled_via_test:
            offending = "disable: true" if disable is True else 'test: ["NONE"]'
            yield Finding(
                rule_id="CL-0015",
                severity=Severity.LOW,
                service=service_name,
                message=(
                    f"Healthcheck is explicitly disabled via {offending}. The "
                    "orchestrator cannot detect or automatically restart "
                    "unhealthy containers."
                ),
                line=lines.get(f"services.{service_name}.healthcheck"),
                fix=(
                    f"Remove '{offending}' and configure a healthcheck:\n"
                    "  healthcheck:\n"
                    '    test: ["CMD", "curl", "-f", "http://localhost/"]\n'
                    "    interval: 30s\n"
                    "    timeout: 10s\n"
                    "    retries: 3"
                ),
                references=[CIS_REF_46, CIS_REF_527],
            )

    def fix(
        self,
        finding: Finding,
        data: dict[str, Any],
        lines: dict[str, int],
        text: str,
    ) -> list[TextEdit] | None:
        """Delete a ``healthcheck:`` block whose only key disables the check.

        ``disable: true`` (or ``test: ["NONE"]``) is an opt-out of the image's
        default healthcheck, so removing the block restores it. Refuses (returns
        ``None``) when the block carries other keys — deleting the disable would
        strand them (e.g. an ``interval`` with no ``test``), a partial block we
        can't safely resolve — and for anchored/merged services or flow-style
        blocks (ADR-014 refusal policy). The edit carries a caveat because
        re-enabling the healthcheck changes runtime behavior. A full-line comment
        sitting inside the block is removed with it; it is treated as belonging
        to the block (issue #261 L5).
        """
        service = finding.service
        services = data.get("services")
        if not isinstance(services, dict):
            return None
        service_config = services.get(service)
        if not isinstance(service_config, dict):
            return None
        healthcheck = service_config.get("healthcheck")
        if not isinstance(healthcheck, dict):
            return None

        disable = healthcheck.get("disable")
        test = healthcheck.get("test")
        if not (disable is True or test == ["NONE"] or test == "NONE"):
            return None

        healthcheck_line = lines.get(f"services.{service}.healthcheck")
        service_line = lines.get(f"services.{service}")
        if healthcheck_line is None or service_line is None:
            return None

        source_lines = text.splitlines(keepends=True)
        n = len(source_lines)
        if not (1 <= service_line <= n and 1 <= healthcheck_line <= n):
            return None

        if is_anchored_or_merged(source_lines, service_line):
            return None
        if not opens_block_body(source_lines[healthcheck_line - 1]):
            return None

        # Other keys alongside the disable directive -> partial block; refuse.
        if len(healthcheck) != 1:
            return None

        # Sole key of the service -> deleting the block would leave the service
        # with a null body (`web:` with no mapping), which no longer parses as
        # Compose. Refuse rather than emit invalid YAML (ADR-014).
        if len(service_config) == 1:
            return None

        first, last = block_span(source_lines, healthcheck_line)
        return [delete_lines(source_lines, first, last, caveat=_CAVEAT)]
