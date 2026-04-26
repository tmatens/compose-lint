"""CL-0017: Shared mount propagation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

CIS_REF = "CIS Docker Benchmark 5.20 — Do not share the host's mount propagation"


@register_rule
class SharedMountRule(BaseRule):
    """Detects services using shared mount propagation."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0017",
            name="Shared mount propagation",
            description=(
                "Shared mount propagation allows mounts created inside a container "
                "to appear on the host filesystem and vice versa, breaking mount "
                "namespace isolation."
            ),
            severity=Severity.MEDIUM,
            references=[CIS_REF],
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

        for i, volume in enumerate(volumes):
            if self._is_shared_short_syntax(volume) or self._is_shared_long_syntax(
                volume
            ):
                yield self._make_finding(service_name, lines, str(volume), i)

    def _is_shared_short_syntax(self, volume: Any) -> bool:
        """Check for :shared suffix in short-syntax volume strings."""
        if not isinstance(volume, str):
            return False
        # Short syntax options field can contain 'shared'
        # e.g., /host:/container:shared or /host:/container:ro,shared
        parts = volume.split(":")
        if len(parts) >= 3:
            options = parts[-1].split(",")
            return "shared" in options
        return False

    def _is_shared_long_syntax(self, volume: Any) -> bool:
        """Check for bind.propagation: shared in long-syntax volumes."""
        if not isinstance(volume, dict):
            return False
        bind = volume.get("bind")
        if not isinstance(bind, dict):
            return False
        propagation = bind.get("propagation")
        return isinstance(propagation, str) and propagation.lower() == "shared"

    def _make_finding(
        self, service_name: str, lines: dict[str, int], volume_str: str, index: int
    ) -> Finding:
        return Finding(
            rule_id="CL-0017",
            severity=Severity.MEDIUM,
            service=service_name,
            message=(
                "Service uses shared mount propagation. Mounts created inside "
                "the container will appear on the host and vice versa."
            ),
            line=lines.get(f"services.{service_name}.volumes[{index}]")
            or lines.get(f"services.{service_name}.volumes"),
            fix=(
                "Remove ':shared' from the volume mount or change "
                "bind.propagation to 'rprivate' (the default):\n"
                "  volumes:\n"
                "    - type: bind\n"
                "      source: /host/path\n"
                "      target: /container/path\n"
                "      bind:\n"
                "        propagation: rprivate"
            ),
            references=[CIS_REF],
        )
