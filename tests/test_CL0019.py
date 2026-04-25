"""Tests for CL-0019: Image tag without digest."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
from compose_lint.rules.CL0019_image_no_digest import ImageNoDigestRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestImageNoDigestRule:
    """Tests for image tag without digest detection."""

    def setup_method(self) -> None:
        self.rule = ImageNoDigestRule()

    def _check(self, service_name: str) -> list:
        data, lines = load_compose(FIXTURES / "insecure_image_no_digest.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def test_detects_version_tag_without_digest(self) -> None:
        findings = self._check("version_tag")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0019"
        assert "nginx:1.25.3" in findings[0].message

    def test_detects_alpine_tag_without_digest(self) -> None:
        findings = self._check("alpine_tag")
        assert len(findings) == 1
        assert "nginx:1.27-alpine" in findings[0].message

    def test_detects_registry_tag_without_digest(self) -> None:
        findings = self._check("registry_tag")
        assert len(findings) == 1
        assert findings[0].message.split("'")[1] == "ghcr.io/org/app:2.0.1"

    def test_digest_pinned_no_findings(self) -> None:
        findings = self._check("digest_pinned")
        assert len(findings) == 0

    def test_no_tag_no_findings(self) -> None:
        """CL-0004 handles missing tags, not CL-0019."""
        findings = self._check("no_tag")
        assert len(findings) == 0

    def test_latest_tag_no_findings(self) -> None:
        """CL-0004 handles mutable tags, not CL-0019."""
        findings = self._check("latest_tag")
        assert len(findings) == 0

    def test_stable_tag_no_findings(self) -> None:
        findings = self._check("stable_tag")
        assert len(findings) == 0

    def test_build_only_no_findings(self) -> None:
        findings = self._check("build_only")
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = self._check("version_tag")
        assert findings[0].fix is not None
        assert "sha256" in findings[0].fix
        assert "Dependabot" in findings[0].fix or "Renovate" in findings[0].fix

    def test_has_references(self) -> None:
        findings = self._check("version_tag")
        assert len(findings[0].references) > 0

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0019"
        assert meta.severity.value == "medium"

    def test_port_registry_pinned_fires(self) -> None:
        findings = self._check("port_registry_pinned")
        assert len(findings) == 1
        assert "localhost:5000/foo:v1.2.3" in findings[0].message

    def test_port_registry_no_tag_no_findings(self) -> None:
        """No tag at all is CL-0004's domain, not CL-0019."""
        findings = self._check("port_registry_no_tag")
        assert len(findings) == 0

    def test_port_registry_digest_no_findings(self) -> None:
        findings = self._check("port_registry_digest")
        assert len(findings) == 0
