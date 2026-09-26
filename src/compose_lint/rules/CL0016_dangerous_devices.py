"""CL-0016: Dangerous host devices exposed."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from compose_lint._scalar import as_scalar_text
from compose_lint.models import Finding, RuleMetadata, Severity
from compose_lint.rules import BaseRule, register_rule
from compose_lint.rules._caps import normalize_cap
from compose_lint.rules._mounts import iter_bind_mounts, normalize_host_path

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
    # A directory source is walked by Docker, which maps every device node
    # beneath it. The node patterns below are all anchored one level down, so
    # the directory itself (normalized, so no trailing slash) needs its own row.
    #
    # Only /dev itself. The walk maps real nodes and skips symlinks, and
    # /dev/disk, /dev/mapper and /dev/md hold (almost) nothing else: measured
    # on two hosts (#913), `--device /dev/disk` is refused outright ("not a
    # device node") and `--device /dev/mapper` maps only `control`, whose
    # ioctls need CAP_SYS_ADMIN (CL-0024). A symlink named *directly* is
    # resolved and does grant the disk, which is why the rows below keep
    # `/dev/disk/`, `/dev/mapper/` and `/dev/md/`.
    (re.compile(r"^/dev$"), "/dev — every host device node, every disk included"),
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
    (re.compile(r"^/dev/zd\d"), "/dev/zd* — ZFS zvol block device"),
    (re.compile(r"^/dev/zvol/"), "/dev/zvol/* — ZFS zvol symlink"),
    (re.compile(r"^/dev/nbd\d"), "/dev/nbd* — network block device"),
    (re.compile(r"^/dev/mtdblock"), "/dev/mtdblock* — MTD flash block device"),
    # Anchored at the end, unlike /dev/sd[a-z]: "hd" plus a letter is also the
    # start of names like /dev/hdmi0 that are not disks.
    (re.compile(r"^/dev/hd[a-z]\d*$"), "/dev/hd* — legacy IDE block device"),
    (re.compile(r"^/dev/kmsg$"), "/dev/kmsg — kernel log buffer read/inject"),
]


def _extract_host_device(device: Any) -> str | None:
    """Extract and normalize the host device path from a device mapping.

    Short syntax is ``/dev/host:/dev/container[:permissions]``, or just
    ``/dev/host``. Long syntax is a mapping whose ``source`` is the host path,
    which is the form `docker compose config` itself renders.

    The path is normalized before the patterns below see it. Every pattern is
    anchored at ``^/dev/``, so the raw form let equivalent spellings through:
    ``//dev/sda`` and ``/dev/./sdb`` name the same device node to the kernel
    and are passed through verbatim by `docker compose config`, but matched
    none of the sixteen patterns. `normalize_host_path` is the collapsing the
    repo already owns and already applies to bind sources.
    """
    if isinstance(device, dict):
        source = device.get("source")
        if not isinstance(source, str):
            return None
        host = source
    elif isinstance(device, str):
        host = device.split(":")[0]
    else:
        return None
    return normalize_host_path(host) if host else host


# `device_cgroup_rules:` entries, in the one shape Docker accepts:
# `<type> <major>:<minor> <access>`. Whitespace is normalized first, so
# `b  8:*   rwm` is the same rule; anything else Docker refuses to start, so it
# describes no running service and is skipped.
_CGROUP_RULE = re.compile(r"^([abc]) (\*|\d+):(\*|\d+) ([rwm]{1,3})$")


def _cgroup_disk_grant(entry: Any) -> tuple[str, str] | None:
    """``(evidence, description)`` for a rule that opens the gate to a disk.

    A device cgroup rule only *permits* a device class; it maps no node. With
    the node present (see :func:`_node_reachable`) a ``b`` rule carrying ``r``
    or ``w`` is a raw read or write of whatever disk has that major, and ``a``
    is every device. Any block major counts, not a table of disk majors: NVMe
    and device-mapper, zvol and nbd disks all sit on dynamically allocated
    majors, so a table would miss the host disk itself (#882, measured). ``m``
    alone permits creating a node, not using it, and grants nothing. ``c``
    rules are not claimed here.

    Evidence is ``<type> <major>:<minor>`` without the access letters: ``r``
    alone is already the whole read, so ``rwm`` → ``r`` is the same finding and
    must not re-key the alert (ADR-024).
    """
    text = as_scalar_text(entry)
    if text is None:
        return None
    match = _CGROUP_RULE.match(" ".join(text.split()))
    if match is None:
        return None
    kind, major, minor, access = match.groups()
    if kind == "c" or not set(access) & {"r", "w"}:
        return None
    evidence = f"{kind} {major}:{minor}"
    if kind == "a":
        return evidence, "every host device, every disk included"
    if major == "*":
        return evidence, "every host block device"
    return evidence, f"every host block device with major {major}"


def _node_reachable(
    service_name: str,
    service_config: dict[str, Any],
    global_config: dict[str, Any],
    lines: dict[str, int],
) -> bool:
    """Whether the container can get a device node for a cgroup rule to open.

    Two ways, both measured (#882). Docker's default ``MKNOD`` capability lets
    it create the node itself. Without it, a bind mount of ``/dev`` or of a
    node beneath it conveys the host's node, and the rule then opens it at
    ``cap_drop: [ALL]``. A service that drops ``MKNOD`` and mounts nothing from
    ``/dev`` holds a rule with no node to use.
    """
    if _keeps_mknod(service_config):
        return True
    for mount in iter_bind_mounts(service_name, service_config, lines, global_config):
        host = normalize_host_path(mount.host_path)
        if host == "/dev" or host.startswith("/dev/"):
            return True
    return False


def _keeps_mknod(service_config: dict[str, Any]) -> bool:
    """Whether ``MKNOD`` survives ``cap_drop`` (and any ``cap_add`` restoring it)."""

    def names(key: str) -> set[str]:
        value = service_config.get(key, [])
        if not isinstance(value, list):
            return set()
        return {normalize_cap(cap) for cap in value}

    if service_config.get("privileged") is True:
        return True
    if names("cap_add") & {"MKNOD", "ALL"}:
        return True
    return not names("cap_drop") & {"MKNOD", "ALL"}


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
                        evidence=host_device,
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

        yield from self._check_cgroup_rules(
            service_name, service_config, global_config, lines
        )

    def _check_cgroup_rules(
        self,
        service_name: str,
        service_config: dict[str, Any],
        global_config: dict[str, Any],
        lines: dict[str, int],
    ) -> Iterator[Finding]:
        """``device_cgroup_rules:`` opening the same gate ``devices:`` does.

        The same Direct x Host cell as a mapped disk, so the same rule and the
        same severity (ADR-028): at default capabilities ``b <major>:* r`` plus
        ``mknod`` read the host disk, verified live (``_cl0016_cgroup_rule``).
        """
        rules = service_config.get("device_cgroup_rules", [])
        if not isinstance(rules, list) or not rules:
            return
        grants = [(i, _cgroup_disk_grant(entry)) for i, entry in enumerate(rules)]
        if not any(grant for _, grant in grants):
            return
        if not _node_reachable(service_name, service_config, global_config, lines):
            return
        for i, grant in grants:
            if grant is None:
                continue
            evidence, description = grant
            yield Finding(
                rule_id="CL-0016",
                severity=Severity.CRITICAL,
                service=service_name,
                evidence=evidence,
                message=(
                    f"Service's device cgroup rule '{evidence}' permits "
                    f"{description}, and the container can obtain the node "
                    "(the default MKNOD capability, or a /dev bind mount)."
                ),
                line=lines.get(f"services.{service_name}.device_cgroup_rules[{i}]")
                or lines.get(f"services.{service_name}.device_cgroup_rules"),
                fix=(
                    f"Remove '{evidence}' from device_cgroup_rules, or narrow it to "
                    "the specific non-disk device the workload needs. If the rule "
                    "must stay, add MKNOD to cap_drop and mount nothing from /dev."
                ),
                references=[CIS_REF],
            )
