"""CL-0016: Dangerous host devices exposed."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._mounts import normalize_host_path

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
#   /dev/fuse            — mount(2) needs CAP_SYS_ADMIN, which CL-0024 flags at
#                          CRITICAL. On an AppArmor host it additionally needs
#                          an unconfined profile (CL-0009): measured, SYS_ADMIN
#                          alone mounts on Arch with no AppArmor and is refused
#                          on Debian 13 with it. That second gate is captured
#                          evidence from the AppArmor host, not a fact that
#                          holds everywhere (ADR-020) — the drop rests on the
#                          SYS_ADMIN gate, which does
#
# Removed as unreachable: /dev/kmem and /dev/raw, for which Docker refuses to
# create the container at all (and CONFIG_DEVKMEM is off on modern kernels).
#
# /dev/kmsg stays despite needing CAP_SYSLOG on this host: dmesg_restrict is a
# *host* sysctl whose upstream default is 0, where the read needs no capability.
# CL-0030 now flags a SYSLOG grant, but that is the capability axis and this is
# the device axis: a file whose only mention of kernel logs is /dev/kmsg carries
# no cap_add for CL-0030 to see, so dropping the device here would leave the
# upstream-default case ungraded.
_DANGEROUS_DEVICE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^/dev/sd[a-z]"), "/dev/sd* — SCSI/SATA block device"),
    (re.compile(r"^/dev/nvme"), "/dev/nvme* — NVMe block device"),
    (re.compile(r"^/dev/vd[a-z]"), "/dev/vd* — virtio block device (KVM, Proxmox)"),
    (re.compile(r"^/dev/xvd[a-z]"), "/dev/xvd* — Xen block device (EC2)"),
    (re.compile(r"^/dev/mmcblk"), "/dev/mmcblk* — SD/eMMC block device (Raspberry Pi)"),
    (re.compile(r"^/dev/md\d"), "/dev/md* — Linux software RAID array"),
    # mdadm also creates a named symlink per array at /dev/md/<name>, which the
    # \d pattern above cannot match. Kept as a separate entry rather than
    # loosening that one to [\d/], because the \d is what keeps /dev/mdadm out.
    (re.compile(r"^/dev/md/"), "/dev/md/* — named software RAID array"),
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
    """Extract and normalize the host device path from a device mapping.

    Format: ``/dev/host:/dev/container[:permissions]``, or just ``/dev/host``.

    The path is normalized before the patterns below see it. Every pattern is
    anchored at ``^/dev/``, so the raw form let equivalent spellings through:
    ``//dev/sda`` and ``/dev/./sdb`` name the same device node to the kernel
    and are passed through verbatim by `docker compose config`, but matched
    none of the sixteen patterns. `normalize_host_path` is the collapsing the
    repo already owns and already applies to bind sources.
    """
    if not isinstance(device, str):
        return None
    host = device.split(":")[0]
    return normalize_host_path(host) if host else host


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
