"""Tests for CL-0030: host-disclosure capability added.

The third rule in the `Direct × Host` cell. CL-0028, CL-0029 and this one all
ship HIGH and are separated only by which qualifier they spend, so a member
placed in the wrong one produces no visible symptom — the severity is right and
the derivation is quietly false. These tests pin the membership boundary.
"""

from __future__ import annotations

from compose_lint.models import Severity
from compose_lint.parser import loads
from compose_lint.rules.CL0028_host_reach_cap_add import HOST_REACH_CAPS
from compose_lint.rules.CL0029_host_availability_cap_add import HOST_AVAILABILITY_CAPS
from compose_lint.rules.CL0030_host_disclosure_cap_add import (
    HOST_DISCLOSURE_CAPS,
    HostDisclosureCapAddRule,
)


class TestHostDisclosureCapAddRule:
    def setup_method(self) -> None:
        self.rule = HostDisclosureCapAddRule()

    def _check(self, caps: str, service: str = "a") -> list:
        content = (
            f"services:\n  {service}:\n    image: nginx:1.27\n    cap_add:\n{caps}"
        )
        data, lines = loads(content)
        return list(self.rule.check(service, data["services"][service], data, lines))

    def test_syslog_fires_at_high(self) -> None:
        findings = self._check("      - SYSLOG\n")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].rule_id == "CL-0030"

    def test_membership_is_exactly_syslog(self) -> None:
        assert set(HOST_DISCLOSURE_CAPS) == {"SYSLOG"}

    def test_the_three_host_cell_rules_stay_disjoint(self) -> None:
        """CL-0028/0029/0030 share a cell and a severity; only the qualifier
        separates them, so an overlap would be invisible in the output."""
        assert not set(HOST_DISCLOSURE_CAPS) & set(HOST_AVAILABILITY_CAPS)
        assert not set(HOST_DISCLOSURE_CAPS) & set(HOST_REACH_CAPS)

    def test_cap_prefix_and_case_are_equivalent(self) -> None:
        for spelling in ("CAP_SYSLOG", "cap_syslog", "syslog", "SYSLOG"):
            findings = self._check(f"      - {spelling}\n")
            assert len(findings) == 1, spelling
            assert spelling.upper() in findings[0].message, spelling

    def test_neighbouring_tiers_are_not_this_rule(self) -> None:
        for cap in ("SYS_TIME", "PERFMON", "SYS_NICE", "IPC_LOCK", "LEASE", "CHOWN"):
            assert self._check(f"      - {cap}\n") == [], cap

    def test_fix_points_at_reading_the_log_on_the_host(self) -> None:
        fix = self._check("      - SYSLOG\n")[0].fix
        assert "journalctl" in fix
        assert fix.endswith("Full guide: compose-lint --explain CL-0030")
