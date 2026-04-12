"""CL-0013: Sensitive host paths mounted."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

OWASP_REF = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Docker_Security_Cheat_Sheet.html#rule-8---set-filesystem-and-volumes-to-read-only"
)

CIS_REF = "CIS Docker Benchmark 5.5 — Do not mount sensitive host system directories"

_SENSITIVE_PATHS = ("/etc", "/proc", "/sys", "/boot", "/root")

# Matches host:container or host:container:mode in short syntax
_SHORT_VOLUME_RE = re.compile(r"^(?P<host>/[^:]+):(?P<container>[^:]+)")


def _extract_host_path(volume: Any) -> str | None:
    """Extract the host path from a short-syntax volume string."""
    if not isinstance(volume, str):
        return None
    m = _SHORT_VOLUME_RE.match(volume)
    if m:
        return m.group("host")
    return None


def _is_sensitive(host_path: str) -> str | None:
    """Return the sensitive prefix if host_path starts with one, else None."""
    # Normalize trailing slashes for comparison
    normalized = host_path.rstrip("/")
    for sensitive in _SENSITIVE_PATHS:
        if normalized == sensitive or normalized.startswith(sensitive + "/"):
            return sensitive
    return None


@register_rule
class SensitiveMountRule(BaseRule):
    """Detects services mounting sensitive host paths."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0013",
            name="Sensitive host path mounted",
            description=(
                "Mounting sensitive host directories like /etc, /proc, /sys, "
                "/boot, or /root into a container exposes host configuration "
                "and kernel interfaces."
            ),
            severity=Severity.HIGH,
            references=[OWASP_REF, CIS_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        volumes = service_config.get("volumes", [])
        if not isinstance(volumes, list):
            return

        for volume in volumes:
            # Short syntax: /host/path:/container/path[:mode]
            host_path = _extract_host_path(volume)
            if (
                host_path is None
                and isinstance(volume, dict)
                and volume.get("type") == "bind"
            ):
                # Long syntax: dict with 'source' key
                source = volume.get("source")
                if isinstance(source, str):
                    host_path = source

            if host_path is None:
                continue

            sensitive = _is_sensitive(host_path)
            if sensitive:
                yield Finding(
                    rule_id="CL-0013",
                    severity=Severity.HIGH,
                    service=service_name,
                    message=(
                        f"Service mounts sensitive host path '{host_path}' "
                        f"(under {sensitive}). This exposes host system files "
                        "to the container."
                    ),
                    line=lines.get(f"services.{service_name}.volumes"),
                    fix=(
                        f"Remove the bind mount for {host_path}. If the container "
                        "needs specific files, copy them into the image at build time "
                        "or use a named volume with only the required data."
                    ),
                    references=[OWASP_REF, CIS_REF],
                )
