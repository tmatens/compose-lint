"""Tests for CL-0029: host-availability capability added.

The fourth `cap_add` tier. What is worth testing here is the boundary with
CL-0028, which sits in the *same* cell (`Direct × Host`) and is separated from
this rule only by which qualifier it spends — so a member landing in the wrong
one is not caught by the severity number, which is HIGH either way.
"""

from __future__ import annotations

from compose_lint.models import Severity
from compose_lint.parser import loads
from compose_lint.rules.CL0029_host_availability_cap_add import (
    HOST_AVAILABILITY_CAPS,
    HostAvailabilityCapAddRule,
)


class TestHostAvailabilityCapAddRule:
    def setup_method(self) -> None:
        self.rule = HostAvailabilityCapAddRule()

    def _check(self, caps: str, service: str = "a") -> list:
        content = (
            f"services:\n  {service}:\n    image: nginx:1.27\n    cap_add:\n{caps}"
        )
        data, lines = loads(content)
        return list(self.rule.check(service, data["services"][service], data, lines))

    def test_each_member_fires_at_high(self) -> None:
        for cap in HOST_AVAILABILITY_CAPS:
            findings = self._check(f"      - {cap}\n")
            assert len(findings) == 1, cap
            assert findings[0].severity == Severity.HIGH, cap
            assert findings[0].rule_id == "CL-0029", cap

    def test_members_are_exactly_the_three_measured_capabilities(self) -> None:
        """Each was measured reaching the host with no sibling key. A capability
        added here without that evidence is the CL-0022/CL-0023 failure mode."""
        assert set(HOST_AVAILABILITY_CAPS) == {"SYS_NICE", "IPC_LOCK", "LEASE"}

    def test_cap_prefix_and_case_are_equivalent(self) -> None:
        for spelling in ("CAP_SYS_NICE", "cap_sys_nice", "sys_nice", "SYS_NICE"):
            findings = self._check(f"      - {spelling}\n")
            assert len(findings) == 1, spelling
            assert spelling.upper() in findings[0].message, spelling

    def test_unrelated_capabilities_are_not_this_rule(self) -> None:
        """The other tiers' members, and a Docker default, must not fire here."""
        for cap in ("SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "PERFMON", "CHOWN"):
            assert self._check(f"      - {cap}\n") == [], cap

    def test_every_member_names_a_bounded_alternative_or_suppression(self) -> None:
        """A finding a reader cannot act on is the defect this rule set treats
        as a bug; SPDK/DPDK workloads genuinely need these."""
        for cap in HOST_AVAILABILITY_CAPS:
            fix = self._check(f"      - {cap}\n")[0].fix
            assert "deploy.resources" in fix or "suppress" in fix, cap
            assert fix.endswith("Full guide: compose-lint --explain CL-0029"), cap

    def test_multiple_members_report_once_each(self) -> None:
        findings = self._check("      - SYS_NICE\n      - IPC_LOCK\n      - LEASE\n")
        assert len(findings) == 3
        assert {f.line for f in findings} == {5, 6, 7}
