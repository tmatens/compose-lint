"""Tests for CL-0017: Shared mount propagation."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
from compose_lint.rules.CL0017_shared_mount import SharedMountRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestSharedMountRule:
    """Tests for shared mount propagation detection."""

    def setup_method(self) -> None:
        self.rule = SharedMountRule()

    def _check(self, service_name: str) -> list:
        data, lines = load_compose(FIXTURES / "insecure_shared_mount.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def test_detects_shared_short_syntax(self) -> None:
        findings = self._check("shared_short")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0017"
        assert "shared mount propagation" in findings[0].message.lower()

    def test_detects_shared_with_other_options(self) -> None:
        findings = self._check("shared_with_ro")
        assert len(findings) == 1

    def test_detects_shared_long_syntax(self) -> None:
        findings = self._check("shared_long")
        assert len(findings) == 1

    def test_rprivate_no_findings(self) -> None:
        findings = self._check("rprivate_long")
        assert len(findings) == 0

    def test_normal_mount_no_findings(self) -> None:
        findings = self._check("normal_mount")
        assert len(findings) == 0

    def test_rw_mount_no_findings(self) -> None:
        findings = self._check("rw_mount")
        assert len(findings) == 0

    def test_no_volumes_no_findings(self) -> None:
        findings = self._check("no_volumes")
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = self._check("shared_short")
        assert findings[0].fix is not None
        assert "rprivate" in findings[0].fix

    def test_has_references(self) -> None:
        findings = self._check("shared_short")
        assert len(findings[0].references) > 0

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0017"
        assert meta.severity.value == "medium"

    def test_safe_named_short_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "safe_named_volume_propagation.yml")
        findings = list(
            self.rule.check("named_short", data["services"]["named_short"], data, lines)
        )
        assert len(findings) == 0

    def test_safe_named_long_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "safe_named_volume_propagation.yml")
        findings = list(
            self.rule.check("named_long", data["services"]["named_long"], data, lines)
        )
        assert len(findings) == 0
