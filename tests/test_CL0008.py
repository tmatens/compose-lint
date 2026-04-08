"""Tests for CL-0008: Host network mode."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
from compose_lint.rules.CL0008_host_network import HostNetworkRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestHostNetworkRule:
    """Tests for host network mode detection."""

    def setup_method(self) -> None:
        self.rule = HostNetworkRule()

    def test_detects_host_network(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_host_network.yml")
        findings = list(
            self.rule.check(
                "host_network", data["services"]["host_network"], data, lines
            )
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0008"
        assert findings[0].severity.value == "error"

    def test_bridge_network_clean(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_host_network.yml")
        findings = list(
            self.rule.check(
                "bridge_network", data["services"]["bridge_network"], data, lines
            )
        )
        assert len(findings) == 0

    def test_service_network_clean(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_host_network.yml")
        findings = list(
            self.rule.check(
                "service_network", data["services"]["service_network"], data, lines
            )
        )
        assert len(findings) == 0

    def test_no_network_mode_clean(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_host_network.yml")
        findings = list(
            self.rule.check(
                "no_network_mode", data["services"]["no_network_mode"], data, lines
            )
        )
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_host_network.yml")
        findings = list(
            self.rule.check(
                "host_network", data["services"]["host_network"], data, lines
            )
        )
        assert findings[0].fix is not None
        assert "bridge" in findings[0].fix.lower()

    def test_has_references(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_host_network.yml")
        findings = list(
            self.rule.check(
                "host_network", data["services"]["host_network"], data, lines
            )
        )
        assert len(findings[0].references) > 0
        assert "owasp" in findings[0].references[0].lower()

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0008"
        assert meta.severity.value == "error"
        assert len(meta.references) > 0
