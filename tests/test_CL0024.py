"""Tests for CL-0024: capabilities that grant host code execution.

The CRITICAL tier of the three-way cap_add split (see tests/test_CL0011.py for
the shape). What matters here is that the tier claims exactly the four
capabilities whose grant is host code execution and nothing weaker — a
false CRITICAL is the most expensive kind of false positive this tool can emit.
"""

from __future__ import annotations

from pathlib import Path

from compose_lint.models import Severity
from compose_lint.parser import load_compose, loads
from compose_lint.rules.CL0024_host_exec_cap_add import HostExecCapAddRule

FIXTURES = Path(__file__).parent / "compose_files"

OTHER_TIERS = (
    "NET_ADMIN",
    "BPF",
    "SYS_BOOT",
    "SYS_PTRACE",
    "PERFMON",
    "SYS_TIME",
    "DAC_READ_SEARCH",
)


class TestHostExecCapAddRule:
    def setup_method(self) -> None:
        self.rule = HostExecCapAddRule()

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
        assert meta.id == "CL-0024"
        assert meta.severity.value == "critical"
        assert len(meta.references) > 0

    def test_detects_each_member_at_critical(self) -> None:
        for cap in ("ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO"):
            findings = self._check_cap(cap)
            assert len(findings) == 1, cap
            assert findings[0].rule_id == "CL-0024"
            assert findings[0].severity == Severity.CRITICAL
            assert cap in findings[0].message

    def test_stays_silent_on_the_other_tiers(self) -> None:
        for cap in OTHER_TIERS:
            assert self._check_cap(cap) == [], f"CL-0024 claimed {cap}"

    def test_all_is_case_insensitive(self) -> None:
        # "CAP_ALL" is deliberately absent here: Docker rejects it outright.
        # See TestCapAllPrefix at the bottom of this file.
        for spelling in ("ALL", "all"):
            findings = self._check_cap(spelling)
            assert len(findings) == 1, spelling
            assert findings[0].severity is Severity.CRITICAL

    def test_lowercase_member_normalized(self) -> None:
        findings = self._check("lowercase_cap")  # cap_add: [sys_module]
        assert len(findings) == 1
        assert "SYS_MODULE" in findings[0].message

    def test_fixture_services(self) -> None:
        """The committed fixture's host-exec services, by name."""
        assert len(self._check("sys_admin")) == 1
        assert len(self._check("cap_all")) == 1
        assert len(self._check("cap_all_lowercase")) == 1
        # all_dangerous names seven caps; three belong to this tier
        # (SYS_ADMIN, SYS_MODULE, SYS_RAWIO).
        assert len(self._check("all_dangerous")) == 3

    def test_safe_caps_no_findings(self) -> None:
        assert self._check("safe_caps") == []
        assert self._check("no_cap_add") == []

    def test_fix_does_not_offer_a_least_privilege_reading(self) -> None:
        """There is no safe subset of these — the fix says so."""
        fix = self._check_cap("SYS_ADMIN")[0].fix
        assert fix is not None
        assert "VM or a host process" in fix


class TestCapAllPrefix:
    """``CAP_ALL`` is not a capability Docker accepts.

    The ``CAP_`` prefix is optional for real capability names, but Docker
    special-cases ``ALL`` before applying it, so ``CAP_ALL`` reaches the
    capability table and is rejected: ``invalid CapAdd: unknown capability:
    "CAP_ALL"``. Treating it as ``ALL`` produced a CRITICAL finding on a file
    that cannot start.
    """

    def _caps(self, cap: str) -> list:
        data, lines = loads(
            f"services:\n  app:\n    image: nginx\n    cap_add:\n      - {cap}\n"
        )
        return list(
            HostExecCapAddRule().check("app", data["services"]["app"], data, lines)
        )

    def test_bare_all_still_fires(self) -> None:
        assert len(self._caps("ALL")) == 1
        assert len(self._caps("all")) == 1

    def test_prefixed_all_is_not_a_capability(self) -> None:
        assert self._caps("CAP_ALL") == []
        assert self._caps("cap_all") == []

    def test_prefix_still_works_for_real_capabilities(self) -> None:
        for spelling in ("SYS_ADMIN", "CAP_SYS_ADMIN", "cap_sys_admin"):
            assert len(self._caps(spelling)) == 1, spelling
