"""Tests for CL-0005: Ports bound to all interfaces."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from compose_lint.fix import apply_edits
from compose_lint.models import Finding, Severity
from compose_lint.parser import load_compose, loads
from compose_lint.rules.CL0005_unbound_ports import UnboundPortsRule

if TYPE_CHECKING:
    from compose_lint.models import TextEdit

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

    def test_detects_sexagesimal_port(self) -> None:
        # `22:22` parsed as the base-60 int 1342 under YAML 1.1, so the colon
        # vanished and the rule found no host mapping (#277 F1). With the parser
        # fixed the port is a string again and the unbound mapping is detected.
        data, lines = loads(
            "services:\n  ssh:\n    image: nginx\n    ports:\n      - 22:22\n"
        )
        findings = list(self.rule.check("ssh", data["services"]["ssh"], data, lines))
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0005"

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


class TestUnboundPortsFix:
    """Tests for the CL-0005 in-scalar bind fix (ADR-014)."""

    def setup_method(self) -> None:
        self.rule = UnboundPortsRule()

    def _fix(
        self, tmp_path: Path, content: str, service: str = "web"
    ) -> list[TextEdit] | None:
        path = tmp_path / "docker-compose.yml"
        path.write_text(content)
        data, lines = load_compose(path)
        findings = list(
            self.rule.check(service, data["services"][service], data, lines)
        )
        assert findings, "expected CL-0005 to fire"
        return self.rule.fix(findings[0], data, lines, content)

    def test_prepends_when_no_bind_address(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    ports:\n      - 8080:80\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert apply_edits(content, edits) == (
            "services:\n  web:\n    ports:\n      - 127.0.0.1:8080:80\n"
        )

    def test_replaces_ipv4_wildcard(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    ports:\n      - 0.0.0.0:8080:80\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert apply_edits(content, edits) == (
            "services:\n  web:\n    ports:\n      - 127.0.0.1:8080:80\n"
        )

    def test_replaces_ipv6_wildcard(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    ports:\n      - '[::]:8080:80'\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert apply_edits(content, edits) == (
            "services:\n  web:\n    ports:\n      - '127.0.0.1:8080:80'\n"
        )

    def test_preserves_protocol_suffix(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    ports:\n      - 0.0.0.0:53:53/udp\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert "127.0.0.1:53:53/udp" in apply_edits(content, edits)

    def test_quoted_scalar_edited_inside_quotes(self, tmp_path: Path) -> None:
        content = 'services:\n  web:\n    ports:\n      - "8080:80"\n'
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert apply_edits(content, edits) == (
            'services:\n  web:\n    ports:\n      - "127.0.0.1:8080:80"\n'
        )

    def test_preserves_trailing_comment(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    ports:\n      - 8080:80  # public\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        result = apply_edits(content, edits)
        assert "127.0.0.1:8080:80" in result
        assert "# public" in result

    def test_edit_carries_caveat(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    ports:\n      - 8080:80\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert edits[0].caveat is not None
        assert "127.0.0.1" in edits[0].caveat

    def test_fix_resolves_finding_and_is_idempotent(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    ports:\n      - 0.0.0.0:8080:80\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        fixed = tmp_path / "fixed.yml"
        fixed.write_text(apply_edits(content, edits))
        data, lines = load_compose(fixed)
        findings = list(self.rule.check("web", data["services"]["web"], data, lines))
        assert findings == []

    def test_only_targeted_port_is_edited(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    ports:\n"
            "      - 127.0.0.1:5432:5432\n"
            "      - 8080:80\n"
        )
        # The first port is already bound, so only the second fires and is fixed.
        path = tmp_path / "docker-compose.yml"
        path.write_text(content)
        data, lines = load_compose(path)
        findings = list(self.rule.check("web", data["services"]["web"], data, lines))
        assert len(findings) == 1
        edits = self.rule.fix(findings[0], data, lines, content)
        assert edits is not None
        assert apply_edits(content, edits) == (
            "services:\n"
            "  web:\n"
            "    ports:\n"
            "      - 127.0.0.1:5432:5432\n"
            "      - 127.0.0.1:8080:80\n"
        )

    def test_refuses_variable_interpolation(self, tmp_path: Path) -> None:
        # The check's numeric host:container regex never matches a $-bearing
        # port, so no finding fires through it. Exercise the fixer's
        # interpolation guard directly with a hand-built finding.
        content = "services:\n  web:\n    ports:\n      - ${HOST_IP}:8080:80\n"
        path = tmp_path / "docker-compose.yml"
        path.write_text(content)
        data, lines = load_compose(path)
        line = lines.get("services.web.ports[0]")
        assert line is not None
        finding = Finding(
            rule_id="CL-0005",
            severity=Severity.HIGH,
            service="web",
            message="unbound",
            line=line,
        )
        assert self.rule.fix(finding, data, lines, content) is None

    def test_long_syntax_inserts_host_ip_when_absent(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    ports:\n"
            "      - target: 80\n"
            "        published: 8080\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert apply_edits(content, edits) == (
            "services:\n"
            "  web:\n"
            "    ports:\n"
            "      - target: 80\n"
            "        host_ip: 127.0.0.1\n"
            "        published: 8080\n"
        )

    def test_long_syntax_insert_carries_caveat(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    ports:\n"
            "      - target: 80\n"
            "        published: 8080\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert edits[0].caveat is not None
        assert "127.0.0.1" in edits[0].caveat

    def test_long_syntax_replaces_quoted_ipv4_wildcard(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    ports:\n"
            "      - target: 443\n"
            "        published: 8443\n"
            '        host_ip: "0.0.0.0"\n'
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert apply_edits(content, edits) == (
            "services:\n"
            "  web:\n"
            "    ports:\n"
            "      - target: 443\n"
            "        published: 8443\n"
            '        host_ip: "127.0.0.1"\n'
        )

    def test_long_syntax_replaces_quoted_ipv6_wildcard(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    ports:\n"
            "      - target: 80\n"
            "        published: 8080\n"
            '        host_ip: "::"\n'
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert '        host_ip: "127.0.0.1"\n' in apply_edits(content, edits)

    def test_long_syntax_replaces_unquoted_wildcard(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    ports:\n"
            "      - target: 80\n"
            "        published: 8080\n"
            "        host_ip: 0.0.0.0\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert "        host_ip: 127.0.0.1\n" in apply_edits(content, edits)

    def test_long_syntax_host_ip_first_key(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    ports:\n"
            "      - host_ip: 0.0.0.0\n"
            "        target: 80\n"
            "        published: 8080\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert "      - host_ip: 127.0.0.1\n" in apply_edits(content, edits)

    def test_long_syntax_preserves_trailing_comment(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    ports:\n"
            "      - target: 80\n"
            "        published: 8080\n"
            "        host_ip: 0.0.0.0  # external\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        result = apply_edits(content, edits)
        assert "host_ip: 127.0.0.1  # external" in result

    def test_long_syntax_fix_resolves_finding_and_is_idempotent(
        self, tmp_path: Path
    ) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    ports:\n"
            "      - target: 80\n"
            "        published: 8080\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        patched = apply_edits(content, edits)
        fixed = tmp_path / "fixed.yml"
        fixed.write_text(patched)
        data, lines = load_compose(fixed)
        findings = list(self.rule.check("web", data["services"]["web"], data, lines))
        assert findings == []
        # A second pass produces no further edit.
        if findings:
            assert self.rule.fix(findings[0], data, lines, patched) is None

    def test_long_syntax_refuses_flow_style(self, tmp_path: Path) -> None:
        content = (
            "services:\n  web:\n    ports:\n      - {target: 80, published: 8080}\n"
        )
        assert self._fix(tmp_path, content) is None

    def test_long_syntax_refuses_empty_host_ip(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    ports:\n"
            "      - target: 80\n"
            "        published: 8080\n"
            "        host_ip:\n"
        )
        assert self._fix(tmp_path, content) is None

    def test_refuses_anchored_service(self, tmp_path: Path) -> None:
        content = "services:\n  web: &websvc\n    ports:\n      - 8080:80\n"
        assert self._fix(tmp_path, content) is None

    def test_refuses_merge_key_service(self, tmp_path: Path) -> None:
        content = (
            "x-base: &base\n"
            "  image: nginx\n"
            "services:\n"
            "  web:\n"
            "    <<: *base\n"
            "    ports:\n"
            "      - 8080:80\n"
        )
        assert self._fix(tmp_path, content) is None
