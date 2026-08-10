"""CL-0016: Dangerous host devices exposed."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule

if TYPE_CHECKING:
    from collections.abc import Iterator

CIS_REF = (
    "CIS Docker Benchmark 5.18 — Ensure that host devices are not "
    "directly exposed to containers"
)

# Devices whose exposure grants reach with the capabilities a container already
# has. That is the axis ADR-020 draws (severity-review §13.3): a device live
# only alongside a capability another rule already flags belongs to *that* rule,
# not here, because it can fire only beside a strictly higher finding or alone
# on a configuration that grants nothing.
#
# Removed for that reason, all verified on Docker 29.1.3 at default capabilities:
#   /dev/mem, /dev/port  — EPERM without CAP_SYS_RAWIO (CL-0024, CRITICAL); and
#                          /dev/mem is bounded to the sub-1MB region even with
#                          it, because CONFIG_STRICT_DEVMEM restricts the rest
#   /dev/fuse            — mount(2) needs CAP_SYS_ADMIN (CL-0024) *and* an
#                          unconfined AppArmor profile (CL-0009), both flagged
#
# Removed as unreachable: /dev/kmem and /dev/raw, for which Docker refuses to
# create the container at all (and CONFIG_DEVKMEM is off on modern kernels).
#
# /dev/kmsg stays despite needing CAP_SYSLOG on this host: dmesg_restrict is a
# *host* sysctl whose upstream default is 0, where the read needs no capability
# — and no rule flags SYSLOG, so nothing else covers it.
_DANGEROUS_DEVICE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^/dev/sd[a-z]"), "/dev/sd* — SCSI/SATA block device"),
    (re.compile(r"^/dev/nvme"), "/dev/nvme* — NVMe block device"),
    (re.compile(r"^/dev/vd[a-z]"), "/dev/vd* — virtio block device (KVM, Proxmox)"),
    (re.compile(r"^/dev/xvd[a-z]"), "/dev/xvd* — Xen block device (EC2)"),
    (re.compile(r"^/dev/mmcblk"), "/dev/mmcblk* — SD/eMMC block device (Raspberry Pi)"),
    (re.compile(r"^/dev/md\d"), "/dev/md* — Linux software RAID array"),
    (re.compile(r"^/dev/disk/"), "/dev/disk/* — block device symlinks"),
    (
        re.compile(r"^/dev/loop"),
        "/dev/loop* — loop device (mount arbitrary disk images)",
    ),
    (re.compile(r"^/dev/dm-"), "/dev/dm-* — device mapper block device"),
    (re.compile(r"^/dev/mapper/"), "/dev/mapper/* — device mapper symlink"),
    (re.compile(r"^/dev/zfs$"), "/dev/zfs — ZFS pool control device"),
    (re.compile(r"^/dev/rbd"), "/dev/rbd* — Ceph RBD block device"),
    (re.compile(r"^/dev/kmsg$"), "/dev/kmsg — kernel log buffer read/inject"),
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
            severity=Severity.CRITICAL,
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

        for i, device in enumerate(devices):
            host_device = _extract_host_device(device)
            if host_device is None:
                continue

            for pattern, description in _DANGEROUS_DEVICE_PATTERNS:
                if pattern.match(host_device):
                    yield Finding(
                        rule_id="CL-0016",
                        severity=Severity.CRITICAL,
                        service=service_name,
                        message=(
                            f"Service exposes dangerous host device "
                            f"'{host_device}' ({description})."
                        ),
                        line=lines.get(f"services.{service_name}.devices[{i}]")
                        or lines.get(f"services.{service_name}.devices"),
                        fix=(
                            f"Remove '{host_device}' from devices. Direct host "
                            "device access bypasses container isolation entirely."
                        ),
                        references=[CIS_REF],
                    )
                    break  # One finding per device
