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
