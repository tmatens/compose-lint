"""Tests for CL-0016: Dangerous host devices exposed."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose, loads
from compose_lint.rules.CL0016_dangerous_devices import DangerousDevicesRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestDangerousDevicesRule:
    """Tests for dangerous host device detection."""

    def setup_method(self) -> None:
        self.rule = DangerousDevicesRule()

    def _check(self, service_name: str) -> list:
        data, lines = load_compose(FIXTURES / "insecure_devices.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def test_detects_virtio_block(self) -> None:
        # /dev/vda is the host root disk on KVM and Proxmox guests.
        findings = self._check("block_vda")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0016"
        assert "/dev/vd" in findings[0].message

    def test_detects_xen_block(self) -> None:
        findings = self._check("block_xvda")
        assert len(findings) == 1
        assert "/dev/xvd" in findings[0].message

    def test_detects_mmc_block(self) -> None:
        findings = self._check("block_mmcblk")
        assert len(findings) == 1
        assert "/dev/mmcblk" in findings[0].message

    def test_detects_md_raid(self) -> None:
        findings = self._check("block_md")
        assert len(findings) == 1
        assert "/dev/md" in findings[0].message

    def test_detects_block_sda(self) -> None:
        findings = self._check("block_sda")
        assert len(findings) == 1
        assert "/dev/sda" in findings[0].message

    def test_detects_block_sda_partition(self) -> None:
        findings = self._check("block_sda1")
        assert len(findings) == 1
        assert "/dev/sda1" in findings[0].message

    def test_detects_nvme(self) -> None:
        findings = self._check("block_nvme")
        assert len(findings) == 1
        assert "/dev/nvme" in findings[0].message

    def test_detects_disk_symlink(self) -> None:
        findings = self._check("disk_symlink")
        assert len(findings) == 1
        assert "/dev/disk/" in findings[0].message

    def test_detects_dev_kmsg(self) -> None:
        findings = self._check("dev_kmsg")
        assert len(findings) == 1
        assert "/dev/kmsg" in findings[0].message

    def test_detects_multiple(self) -> None:
        findings = self._check("multiple")
        assert len(findings) == 2

    def test_safe_device_no_findings(self) -> None:
        findings = self._check("safe_device")
        assert len(findings) == 0

    def test_no_devices_no_findings(self) -> None:
        findings = self._check("no_devices")
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = self._check("block_sda")
        assert findings[0].fix is not None
        assert "/dev/sda" in findings[0].fix

    def test_has_references(self) -> None:
        findings = self._check("block_sda")
        assert len(findings[0].references) > 0

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0016"
        assert meta.severity.value == "critical"


class TestMembershipBoundary:
    """Devices this rule deliberately does not claim.

    ADR-020 puts a device that is live only alongside a capability another rule
    already flags with *that* rule: it could otherwise fire only beside a
    strictly higher finding, or alone on a configuration that grants nothing.
    Verified at default capabilities on Docker 29.1.3 -- /dev/mem and /dev/port
    are EPERM without CAP_SYS_RAWIO, and /dev/fuse's mount(2) needs
    CAP_SYS_ADMIN plus an unconfined AppArmor profile. /dev/kmem and /dev/raw
    go for a different reason: Docker refuses to create the container at all.
    """

    def setup_method(self) -> None:
        self.rule = DangerousDevicesRule()

    def _check(self, service_name: str) -> list:
        data, lines = load_compose(FIXTURES / "insecure_devices.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def test_capability_gated_devices_are_not_this_rule(self) -> None:
        assert self._check("capability_gated") == []

    def test_unreachable_devices_are_not_flagged(self) -> None:
        assert self._check("unreachable_devices") == []


class TestNamedRaidArrays:
    """mdadm's /dev/md/<name> symlinks are the same device class as /dev/md0.

    ``^/dev/md\\d`` cannot match them -- the character after "md" is "/", not a
    digit -- so a named array was unflagged while the numeric node beside it
    was CRITICAL. The \\d is kept as-is and a second pattern added, because \\d
    is what keeps /dev/mdadm out.
    """

    def setup_method(self) -> None:
        self.rule = DangerousDevicesRule()

    def _findings(self, device: str) -> list:
        data, lines = loads(
            f'services:\n  svc:\n    image: nginx\n    devices: ["{device}:{device}"]\n'
        )
        return list(self.rule.check("svc", data["services"]["svc"], data, lines))

    def test_named_array_is_flagged(self) -> None:
        for device in ("/dev/md/0", "/dev/md/raid1", "/dev/md/data"):
            assert len(self._findings(device)) == 1, device

    def test_numeric_node_still_flagged(self) -> None:
        for device in ("/dev/md0", "/dev/md127"):
            assert len(self._findings(device)) == 1, device

    def test_mdadm_is_not_a_device(self) -> None:
        # The over-match the \d guards against; /dev/md/ must not reopen it.
        assert self._findings("/dev/mdadm") == []


def _device_findings(devices_yaml: str) -> list:
    data, lines = loads(
        "services:\n  svc:\n    image: nginx\n    devices:\n" + devices_yaml
    )
    return list(
        DangerousDevicesRule().check("svc", data["services"]["svc"], data, lines)
    )


class TestLongSyntax:
    """The mapping form is what `docker compose config` itself renders.

    `_extract_host_device` returned None for every non-string entry, so the
    canonical spelling of a raw-disk grant never reached the pattern table.
    """

    def test_long_syntax_block_device_is_flagged(self) -> None:
        findings = _device_findings(
            "      - source: /dev/sda\n"
            "        target: /dev/sda\n"
            "        permissions: rwm\n"
        )
        assert len(findings) == 1
        assert findings[0].evidence == "/dev/sda"
        assert findings[0].line == 5

    def test_long_syntax_source_is_normalized(self) -> None:
        findings = _device_findings("      - source: //dev/./nvme0n1\n")
        assert [f.evidence for f in findings] == ["/dev/nvme0n1"]

    def test_long_syntax_safe_device_is_not_flagged(self) -> None:
        assert (
            _device_findings(
                "      - source: /dev/net/tun\n        target: /dev/net/tun\n"
            )
            == []
        )

    def test_long_syntax_without_source_is_ignored(self) -> None:
        assert _device_findings("      - target: /dev/sda\n") == []
        assert _device_findings("      - source: 42\n") == []


class TestDirectoryGrants:
    """Docker walks a directory source and maps every device node beneath it.

    `/dev:/dev` grants every block device the host has, and each of the
    subdirectories below grants the class of node the rule already flags one at
    a time. Every existing pattern is anchored below the directory itself.
    """

    def test_whole_dev_is_flagged(self) -> None:
        for spelling in ("/dev", "/dev/", "//dev", "/dev/."):
            findings = _device_findings(f'      - "{spelling}:/dev"\n')
            assert [f.evidence for f in findings] == ["/dev"], spelling

    def test_block_subdirectories_are_flagged(self) -> None:
        for directory in ("/dev/mapper", "/dev/disk", "/dev/md"):
            findings = _device_findings(f'      - "{directory}/:{directory}"\n')
            assert [f.evidence for f in findings] == [directory], directory

    def test_long_syntax_directory_is_flagged(self) -> None:
        findings = _device_findings("      - source: /dev\n        target: /dev\n")
        assert [f.evidence for f in findings] == ["/dev"]

    def test_other_device_directories_are_not_flagged(self) -> None:
        for directory in ("/dev/net", "/dev/snd", "/dev/dri", "/dev/bus/usb"):
            assert _device_findings(f'      - "{directory}:{directory}"\n') == [], (
                directory
            )


class TestAdditionalBlockFamilies:
    """Raw block-device node families the table did not enumerate."""

    def test_new_families_are_flagged(self) -> None:
        for device in (
            "/dev/zd0",
            "/dev/zd16",
            "/dev/zvol/tank/vm-100-disk-0",
            "/dev/nbd0",
            "/dev/nbd15",
            "/dev/mtdblock0",
            "/dev/hda",
            "/dev/hdb1",
        ):
            findings = _device_findings(f'      - "{device}:{device}"\n')
            assert [f.evidence for f in findings] == [device], device

    def test_near_misses_are_not_flagged(self) -> None:
        for device in ("/dev/zero", "/dev/hdmi0", "/dev/hidraw0", "/dev/mtd0"):
            assert _device_findings(f'      - "{device}:{device}"\n') == [], device
