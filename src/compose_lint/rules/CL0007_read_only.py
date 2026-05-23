"""CL-0007: Filesystem not read-only."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.fix import (
    first_child_indent,
    is_anchored_or_merged,
)
from compose_lint.models import Finding, RuleMetadata, Severity, TextEdit
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

_CAVEAT = (
    "read_only: true breaks the container if it writes to its root filesystem; "
    "declare writable paths via tmpfs/volumes first."
)

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-8---set-filesystem-and-volumes-to-read-only"
)

CIS_REF = "CIS Docker Benchmark 5.12 — Mount container's root filesystem as read only"


@register_rule
class ReadOnlyFilesystemRule(BaseRule):
    """Detects services without a read-only root filesystem."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0007",
            name="Filesystem not read-only",
            description=(
                "A writable root filesystem allows attackers to modify binaries, "
                "install backdoors, or persist malware inside the container."
            ),
            severity=Severity.MEDIUM,
            references=[OWASP_REF, CIS_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        if service_config.get("read_only") is not True:
            yield Finding(
                rule_id="CL-0007",
                severity=Severity.MEDIUM,
                service=service_name,
                message=(
                    "Service root filesystem is writable. An attacker can modify "
                    "binaries, install tools, or persist malware inside the container."
                ),
                line=lines.get(f"services.{service_name}"),
                fix=(
                    "Set the root filesystem to read-only and declare "
                    "writable paths:\n"
                    "  read_only: true\n"
                    "  tmpfs:\n"
                    "    - /tmp\n"
                    "    - /run\n"
                    "Note: run once without read_only and check "
                    "`docker diff` first."
                ),
                references=[OWASP_REF, CIS_REF],
            )

    def fix(
        self,
        finding: Finding,
        data: dict[str, Any],
        lines: dict[str, int],
        text: str,
    ) -> list[TextEdit] | None:
        """Insert ``read_only: true`` as the first child of the service.

        Refuses (returns ``None``) when the service is flow-style, anchored or
        aliased, uses a merge key, has no determinable child indentation, or
        already declares ``read_only`` (the explicit-value case is deferred).
        The edit carries a caveat because making the rootfs read-only changes
        runtime behavior (ADR-014).
        """
        service = finding.service
        services = data.get("services")
        if not isinstance(services, dict):
            return None
        service_config = services.get(service)
        if not isinstance(service_config, dict):
            return None
        # read_only present but not True is a modify, not an insert; deferred.
        if "read_only" in service_config:
            return None

        key_line = lines.get(f"services.{service}")
        if key_line is None:
            return None
        source_lines = text.splitlines(keepends=True)
        if not 1 <= key_line <= len(source_lines):
            return None

        # Refuse inline/flow/anchored/merge-key services: no plain block body to
        # insert a child into, or an ambiguous edit target (ADR-014).
        if is_anchored_or_merged(source_lines, key_line):
            return None

        child_indent = first_child_indent(source_lines, key_line)
        if child_indent is None:
            return None

        return [
            TextEdit(
                start_line=key_line + 1,
                start_col=1,
                end_line=key_line + 1,
                end_col=1,
                replacement=f"{' ' * child_indent}read_only: true\n",
                caveat=_CAVEAT,
            )
        ]
