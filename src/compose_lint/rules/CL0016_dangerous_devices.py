"""CL-0016: Dangerous host devices exposed."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

CIS_REF = (
    "CIS Docker Benchmark 5.18 — Do not directly expose host devices to containers"
)

_DANGEROUS_DEVICE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^/dev/mem$"), "/dev/mem — raw physical memory access"),
    (re.compile(r"^/dev/kmem$"), "/dev/kmem — kernel virtual memory access"),
    (re.compile(r"^/dev/port$"), "/dev/port — raw I/O port access"),
    (re.compile(r"^/dev/sd[a-z]"), "/dev/sd* — SCSI/SATA block device"),
    (re.compile(r"^/dev/nvme"), "/dev/nvme* — NVMe block device"),
    (re.compile(r"^/dev/disk/"), "/dev/disk/* — block device symlinks"),
]


def _extract_host_device(device: Any) -> str | None:
    """Extract the host device path from a device mapping string."""
    if not isinstance(device, str):
        return None
    # Format: /dev/host:/dev/container[:permissions]
    # or just /dev/host
    return device.split(":")[0]


@register_rule
class DangerousDevicesRule(BaseRule):
    """Detects services exposing dangerous host devices."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="CL-0016",
            name="Dangerous host device exposed",
            description=(
                "Exposing raw memory, I/O ports, or block devices to a container "
                "enables direct hardware access that bypasses all container isolation."
            ),
            severity=Severity.HIGH,
            references=[CIS_REF],
        )

    def check(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        devices = service_config.get("devices", [])
        if not isinstance(devices, list):
            return

        for device in devices:
            host_device = _extract_host_device(device)
            if host_device is None:
                continue

            for pattern, description in _DANGEROUS_DEVICE_PATTERNS:
                if pattern.match(host_device):
                    yield Finding(
                        rule_id="CL-0016",
                        severity=Severity.HIGH,
                        service=service_name,
                        message=(
                            f"Service exposes dangerous host device "
                            f"'{host_device}' ({description})."
                        ),
                        line=lines.get(f"services.{service_name}.devices"),
                        fix=(
                            f"Remove '{host_device}' from devices. Direct host "
                            "device access bypasses container isolation entirely."
                        ),
                        references=[CIS_REF],
                    )
                    break  # One finding per device
