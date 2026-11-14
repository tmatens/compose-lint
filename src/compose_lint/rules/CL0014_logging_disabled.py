"""CL-0014: Logging driver disabled."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint._lines import split_lines
from compose_lint._yaml_edit import (
    INTERPOLATED_DELETION,
    block_span,
    delete_lines,
    is_anchored_or_merged,
    opens_block_body,
)
from compose_lint.models import Finding, FixRefusal, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

    from compose_lint.models import TextEdit

_CAVEAT = (
    "Re-enabling logging restores the default driver; the container's logs are "
    "collected again, which consumes disk and I/O."
)

# Why the fixer leaves a service that uses ``extends:`` alone. Deleting the
# local block is only "restore the default" when nothing else supplies one,
# and a base service can: its ``logging:`` takes effect the moment the local
# opt-out is gone, so the file would deploy the base's driver and options
# while the caveat promised Docker's default (#1252).
INHERITED_LOGGING = (
    "the service uses extends:, and a logging: block it inherits would take "
    "effect once this one is removed, so deleting it is not known to restore "
    "the default driver"
)

DOCKER_REF = "https://docs.docker.com/engine/logging/configure/"
OWASP_REF = "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"
# A daemon-level control: it asks for a logging driver that ships logs off the
# host. A service that sets `driver: none` opts out of whatever the daemon is
# configured to do, so the rule relates to 2.14 and cannot satisfy it.
CIS_REF = (
    "CIS Docker Benchmark 2.14 — Ensure centralized and remote logging is configured"
)


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
            severity=Severity.LOW,
            references=[DOCKER_REF, OWASP_REF, CIS_REF],
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
                severity=Severity.LOW,
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
                references=[DOCKER_REF, OWASP_REF, CIS_REF],
            )

    def fix_writes_keys(self) -> frozenset[str]:
        """It deletes the `logging` block."""
        return frozenset({"logging"})

    def fix(
        self,
        finding: Finding,
        data: dict[str, Any],
        lines: dict[str, int],
        text: str,
    ) -> list[TextEdit] | FixRefusal | None:
        """Delete a ``logging:`` block whose only directive is ``driver: none``.

        ``driver: none`` is an opt-out of the platform default, so removing the
        block restores default logging. Refuses (returns ``None``) when the
        block carries other keys (e.g. ``options:``) — deleting just the driver
        would leave a structurally partial block we can't safely resolve — and
        for anchored/merged services or flow-style blocks (ADR-014 refusal
        policy). Refuses with a reason for a service that uses ``extends:``,
        which can inherit a ``logging:`` block (:data:`INHERITED_LOGGING`).
        The edit carries a caveat because re-enabling logging changes
        runtime behavior. A full-line comment sitting inside the block is removed
        with it; it is treated as belonging to the block (issue #261 L5).
        """
        service = finding.service
        services = data.get("services")
        if not isinstance(services, dict):
            return None
        service_config = services.get(service)
        if not isinstance(service_config, dict):
            return None
        logging_config = service_config.get("logging")
        if not isinstance(logging_config, dict):
            return None
        driver = logging_config.get("driver")
        if not (isinstance(driver, str) and driver.lower() == "none"):
            return None

        logging_line = lines.get(f"services.{service}.logging")
        service_line = lines.get(f"services.{service}")
        if logging_line is None or service_line is None:
            return None

        source_lines = split_lines(text)
        n = len(source_lines)
        if not (1 <= service_line <= n and 1 <= logging_line <= n):
            return None

        if is_anchored_or_merged(source_lines, service_line):
            return None
        if not opens_block_body(source_lines[logging_line - 1]):
            return None

        if "extends" in service_config:
            return FixRefusal(INHERITED_LOGGING)

        # Other keys alongside the driver -> partial block; refuse.
        if len(logging_config) != 1:
            return None

        # Sole key of the service -> deleting the block would leave the service
        # with a null body (`web:` with no mapping), which no longer parses as
        # Compose. Refuse rather than emit invalid YAML (ADR-014).
        if len(service_config) == 1:
            return None

        first, last = block_span(source_lines, logging_line)
        if any("$" in raw for raw in source_lines[first - 1 : last]):
            # `driver: ${LOG_DRIVER:-none}` is `none` only under the default;
            # the deployed driver may be set elsewhere, so the block is not
            # known to be the opt-out it looks like here (ADR-014).
            return FixRefusal(INTERPOLATED_DELETION)
        return [delete_lines(source_lines, first, last, caveat=_CAVEAT)]
