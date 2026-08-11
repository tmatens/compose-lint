"""Tests for CL-0028: capabilities whose reach lands on the host.

The HIGH tier of the four-way ``cap_add`` split. These two were CL-0027's
members until the split. They did not belong there: CL-0027's cell is
``Second flaw × Single container``, and both of these reach the host with no
sibling key and nothing from the image, which is ``Direct × Host``. Priced as
one rule, CL-0027 had to set them aside as "scoping assumptions" -- a clause
the model reserves for reach that *depends* on a sibling key.
"""

from __future__ import annotations

from pathlib import Path

from compose_lint.models import Severity
from compose_lint.parser import load_compose, loads
from compose_lint.rules.CL0028_host_reach_cap_add import HostReachCapAddRule

FIXTURES = Path(__file__).parent / "compose_files"

OTHER_TIERS = (
    "ALL",
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_RAWIO",
    "NET_ADMIN",
    "BPF",
    "SYS_BOOT",
    "SYS_PTRACE",
    "DAC_READ_SEARCH",
)


class TestHostReachCapAddRule:
    def setup_method(self) -> None:
        self.rule = HostReachCapAddRule()

    def _check(self, service_name: str) -> list:
        data, lines = load_compose(FIXTURES / "insecure_cap_add.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def _check_cap(self, cap: str) -> list:
        data, lines = loads(
            f"services:\n  a:\n    image: nginx:1.27\n    cap_add: [{cap}]\n"
        )
        return list(self.rule.check("a", data["services"]["a"], data, lines))

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0028"
        assert meta.severity.value == "high"
        assert len(meta.references) > 0

    def test_detects_each_member_at_high(self) -> None:
        for cap in ("PERFMON", "SYS_TIME"):
            findings = self._check_cap(cap)
            assert len(findings) == 1, cap
            assert findings[0].rule_id == "CL-0028"
            assert findings[0].severity == Severity.HIGH
            assert cap in findings[0].message

    def test_stays_silent_on_the_other_tiers(self) -> None:
        for cap in OTHER_TIERS:
            assert self._check_cap(cap) == [], f"CL-0028 claimed {cap}"

    def test_sys_time_message_says_the_clock_is_host_global(self) -> None:
        """The reach is the whole point of the tier, so the message states it."""
        assert "host-global" in self._check_cap("SYS_TIME")[0].message

    def test_perfmon_message_says_the_read_covers_the_host(self) -> None:
        assert "whole host" in self._check_cap("PERFMON")[0].message

    def test_fix_points_at_the_host_alternative(self) -> None:
        fix = self._check_cap("SYS_TIME")[0].fix
        assert fix is not None
        assert "NTP" in fix

    def test_prefixed_spelling_is_normalised(self) -> None:
        assert len(self._check_cap("CAP_SYS_TIME")) == 1

    def test_fixture_services(self) -> None:
        # all_dangerous names seven caps; one belongs to this tier (SYS_TIME).
        assert len(self._check("all_dangerous")) == 1
        assert self._check("safe_caps") == []
        assert self._check("no_cap_add") == []
