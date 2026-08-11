"""Tests for CL-0027: capabilities with a bounded grant.

The MEDIUM tier of the four-way cap_add split (see tests/test_CL0011.py). This
tier exists as a precision win: debuggers legitimately need these, and grading
them alongside escape paths made the higher tiers less believable.

PERFMON and SYS_TIME are deliberately *not* here -- they reach the host with no
sibling key and nothing from the image, so they are CL-0028's.
"""

from __future__ import annotations

from pathlib import Path

from compose_lint.models import Severity
from compose_lint.parser import load_compose, loads
from compose_lint.rules.CL0027_lesser_cap_add import LesserCapAddRule

FIXTURES = Path(__file__).parent / "compose_files"

OTHER_TIERS = (
    "ALL",
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_RAWIO",
    "NET_ADMIN",
    "BPF",
    "SYS_BOOT",
    "PERFMON",
    "SYS_TIME",
)


class TestLesserCapAddRule:
    def setup_method(self) -> None:
        self.rule = LesserCapAddRule()

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
        assert meta.id == "CL-0027"
        assert meta.severity.value == "medium"
        assert len(meta.references) > 0

    def test_detects_each_member_at_medium(self) -> None:
        for cap in ("SYS_PTRACE", "DAC_READ_SEARCH"):
            findings = self._check_cap(cap)
            assert len(findings) == 1, cap
            assert findings[0].rule_id == "CL-0027"
            assert findings[0].severity == Severity.MEDIUM
            assert cap in findings[0].message

    def test_stays_silent_on_the_other_tiers(self) -> None:
        for cap in OTHER_TIERS:
            assert self._check_cap(cap) == [], f"CL-0027 claimed {cap}"

    def test_sys_ptrace_message_scopes_the_reach(self) -> None:
        """ptrace is confined to the container's own PID namespace."""
        assert "PID namespace" in self._check_cap("SYS_PTRACE")[0].message

    def test_dac_read_search_message_names_its_precondition(self) -> None:
        """The host read needs a bind mount, which another rule flags."""
        assert "bind mount" in self._check_cap("DAC_READ_SEARCH")[0].message

    def test_fix_names_the_legitimate_workload(self) -> None:
        fix = self._check_cap("SYS_PTRACE")[0].fix
        assert fix is not None
        assert "debugger" in fix

    def test_fixture_services(self) -> None:
        """The committed fixture's bounded-grant services, by name."""
        assert len(self._check("sys_ptrace")) == 1
        # all_dangerous names seven caps; two belong to this tier
        # (SYS_PTRACE, DAC_READ_SEARCH). SYS_TIME moved to CL-0028.
        assert len(self._check("all_dangerous")) == 2

    def test_safe_caps_no_findings(self) -> None:
        assert self._check("safe_caps") == []
        assert self._check("no_cap_add") == []
