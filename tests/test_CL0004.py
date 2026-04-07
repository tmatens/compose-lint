"""Tests for CL-0004: Image not pinned to version."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
from compose_lint.rules.CL0004_image_not_pinned import ImageNotPinnedRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestImageNotPinnedRule:
    """Tests for image tag pinning detection."""

    def setup_method(self) -> None:
        self.rule = ImageNotPinnedRule()

    def _check(self, service_name: str, fixture: str = "insecure_image_tags.yml") -> list:
        data, lines = load_compose(FIXTURES / fixture)
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def test_detects_no_tag(self) -> None:
        findings = self._check("no_tag")
        assert len(findings) == 1
        assert "no tag" in findings[0].message.lower()

    def test_detects_latest_tag(self) -> None:
        findings = self._check("latest_tag")
        assert len(findings) == 1
        assert "latest" in findings[0].message

    def test_detects_stable_tag(self) -> None:
        findings = self._check("stable_tag")
        assert len(findings) == 1
        assert "stable" in findings[0].message

    def test_pinned_version_no_findings(self) -> None:
        findings = self._check("pinned")
        assert len(findings) == 0

    def test_digest_pinned_no_findings(self) -> None:
        findings = self._check("digest_pinned")
        assert len(findings) == 0

    def test_build_only_no_findings(self) -> None:
        findings = self._check("build_only")
        assert len(findings) == 0

    def test_registry_prefix_no_tag(self) -> None:
        findings = self._check("registry_no_tag")
        assert len(findings) == 1

    def test_registry_prefix_latest(self) -> None:
        findings = self._check("registry_latest")
        assert len(findings) == 1

    def test_registry_prefix_pinned(self) -> None:
        findings = self._check("registry_pinned")
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = self._check("no_tag")
        assert findings[0].fix is not None

    def test_has_references(self) -> None:
        assert len(self.rule.metadata.references) > 0
