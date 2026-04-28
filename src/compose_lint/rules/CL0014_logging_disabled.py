"""CL-0014: Logging driver disabled."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

DOCKER_REF = "https://docs.docker.com/engine/logging/configure/"
OWASP_REF = "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"


@register_rule
class LoggingDisabledRule(BaseRule):
    """Detects services with logging explicitly disabled."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0014",
            name="Logging driver disabled",
            description=(
                "Setting the logging driver to 'none' prevents all log "
                "collection, making incident response and forensics impossible."
            ),
            severity=Severity.MEDIUM,
            references=[DOCKER_REF, OWASP_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        logging_config = service_config.get("logging")
        if not isinstance(logging_config, dict):
            return

        driver = logging_config.get("driver")
        if isinstance(driver, str) and driver.lower() == "none":
            yield Finding(
                rule_id="CL-0014",
                severity=Severity.MEDIUM,
                service=service_name,
                message=(
                    "Logging driver is set to 'none'. No logs will be collected "
                    "from this container, preventing audit trails and incident "
                    "response."
                ),
                line=lines.get(f"services.{service_name}.logging.driver"),
                fix=(
                    "Remove 'driver: none' to use the default logging driver, "
                    "or configure an appropriate driver:\n"
                    "  logging:\n"
                    "    driver: json-file\n"
                    "    options:\n"
                    "      max-size: 10m\n"
                    "      max-file: '3'"
                ),
                references=[DOCKER_REF, OWASP_REF],
            )
