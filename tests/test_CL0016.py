"""Tests for CL-0016: Dangerous host devices exposed."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
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

    def test_detects_dev_mem(self) -> None:
        findings = self._check("dev_mem")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0016"
        assert "/dev/mem" in findings[0].message

    def test_detects_dev_kmem(self) -> None:
        findings = self._check("dev_kmem")
        assert len(findings) == 1
        assert "/dev/kmem" in findings[0].message

    def test_detects_dev_port(self) -> None:
        findings = self._check("dev_port")
        assert len(findings) == 1
        assert "/dev/port" in findings[0].message

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
        findings = self._check("dev_mem")
        assert findings[0].fix is not None
        assert "/dev/mem" in findings[0].fix

    def test_has_references(self) -> None:
        findings = self._check("dev_mem")
        assert len(findings[0].references) > 0

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0016"
        assert meta.severity.value == "high"
