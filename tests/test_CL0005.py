"""Tests for CL-0005: Ports bound to all interfaces."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
from compose_lint.rules.CL0005_unbound_ports import UnboundPortsRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestUnboundPortsRule:
    """Tests for unbound port detection."""

    def setup_method(self) -> None:
        self.rule = UnboundPortsRule()

    def _check(self, service_name: str) -> list:
        data, lines = load_compose(FIXTURES / "insecure_ports.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def test_detects_unbound_short_syntax(self) -> None:
        findings = self._check("unbound_short")
        assert len(findings) == 2
        assert all(f.rule_id == "CL-0005" for f in findings)

    def test_bound_short_syntax_no_findings(self) -> None:
        findings = self._check("bound_short")
        assert len(findings) == 0

    def test_detects_unbound_long_syntax(self) -> None:
        findings = self._check("unbound_long")
        assert len(findings) == 1

    def test_bound_long_syntax_no_findings(self) -> None:
        findings = self._check("bound_long")
        assert len(findings) == 0

    def test_container_only_port_no_findings(self) -> None:
        findings = self._check("container_only")
        assert len(findings) == 0

    def test_port_range(self) -> None:
        findings = self._check("port_range")
        assert len(findings) == 1

    def test_no_ports_no_findings(self) -> None:
        findings = self._check("no_ports")
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = self._check("unbound_short")
        assert findings[0].fix is not None
        assert "127.0.0.1" in findings[0].fix

    def test_has_references(self) -> None:
        assert len(self.rule.metadata.references) > 0
        assert "owasp" in self.rule.metadata.references[0].lower()

    def test_detects_ipv6_wildcard_short(self) -> None:
        findings = self._check("ipv6_wildcard_short")
        assert len(findings) == 1
        assert "[::]:8080:80" in findings[0].message

    def test_ipv6_loopback_short_no_findings(self) -> None:
        findings = self._check("ipv6_loopback_short")
        assert len(findings) == 0

    def test_detects_ipv4_wildcard_short(self) -> None:
        findings = self._check("ipv4_wildcard_short")
        assert len(findings) == 1
        assert "0.0.0.0:8080:80" in findings[0].message

    def test_detects_long_ipv6_wildcard(self) -> None:
        findings = self._check("long_ipv6_wildcard")
        assert len(findings) == 1

    def test_detects_long_ipv4_wildcard(self) -> None:
        findings = self._check("long_ipv4_wildcard")
        assert len(findings) == 1

    def test_long_ipv6_loopback_no_findings(self) -> None:
        findings = self._check("long_ipv6_loopback")
        assert len(findings) == 0
