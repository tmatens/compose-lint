"""Tests for CL-0023: Dangerous network sysctl enabled."""

from __future__ import annotations

from compose_lint.parser import loads
from compose_lint.rules.CL0023_dangerous_sysctls import (
    DOCKER_REF,
    DangerousSysctlsRule,
)


class TestDangerousSysctlsRule:
    """Detection of escape-adjacent net.* sysctls."""

    def setup_method(self) -> None:
        self.rule = DangerousSysctlsRule()

    def _check(self, body: str) -> list:
        content = f"services:\n  a:\n    image: nginx:1.27\n{body}"
        data, lines = loads(content)
        return list(self.rule.check("a", data["services"]["a"], data, lines))

    def test_detects_ip_forward_map_form(self) -> None:
        findings = self._check("    sysctls:\n      net.ipv4.ip_forward: 1\n")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0023"
        assert findings[0].severity.value == "medium"
        assert "net.ipv4.ip_forward" in findings[0].message

    def test_detects_ip_forward_quoted_value(self) -> None:
        findings = self._check('    sysctls:\n      net.ipv4.ip_forward: "1"\n')
        assert len(findings) == 1

    def test_detects_list_form(self) -> None:
        findings = self._check("    sysctls:\n      - net.ipv6.conf.all.forwarding=1\n")
        assert len(findings) == 1
        assert "forwarding" in findings[0].message

    def test_detects_redirects_and_source_route(self) -> None:
        findings = self._check(
            "    sysctls:\n"
            "      net.ipv4.conf.all.accept_source_route: 1\n"
            "      net.ipv4.conf.all.accept_redirects: 1\n"
            "      net.ipv4.conf.all.send_redirects: 1\n"
        )
        assert len(findings) == 3

    def test_value_zero_is_clean(self) -> None:
        assert self._check("    sysctls:\n      net.ipv4.ip_forward: 0\n") == []

    def test_unlisted_sysctl_is_clean(self) -> None:
        # A benign tuning sysctl is not in the dangerous set.
        assert self._check("    sysctls:\n      net.core.somaxconn: 1024\n") == []

    def test_no_sysctls_is_clean(self) -> None:
        assert self._check("    read_only: true\n") == []

    def test_points_at_the_offending_line(self) -> None:
        findings = self._check("    sysctls:\n      net.ipv4.ip_forward: 1\n")
        # Line 5: services(1) a(2) image(3) sysctls(4) ip_forward(5).
        assert findings[0].line == 5

    def test_metadata_and_references(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0023"
        assert meta.severity.value == "medium"
        assert DOCKER_REF in meta.references

    def test_has_fix_guidance(self) -> None:
        findings = self._check("    sysctls:\n      net.ipv4.ip_forward: 1\n")
        assert findings[0].fix is not None
        assert "0" in findings[0].fix
