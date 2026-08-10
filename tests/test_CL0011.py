"""Tests for CL-0011: strong host-adjacent capabilities added.

CL-0011 is one of three rules over ``cap_add``, split by what the capability
grants (``docs/severity.md``): CL-0024 for host code execution, CL-0011 here
for the strong host-adjacent tier, CL-0027 for the bounded grants. The
membership boundary is the thing worth testing — each rule must claim its own
capabilities and stay silent on the other tiers', or a config gets graded
twice.
"""

from __future__ import annotations

from pathlib import Path

from compose_lint.models import Severity
from compose_lint.parser import load_compose, loads
from compose_lint.rules.CL0011_dangerous_cap_add import DangerousCapAddRule

FIXTURES = Path(__file__).parent / "compose_files"

# Capabilities owned by the other two tiers. CL-0011 must not fire on any.
OTHER_TIERS = (
    "ALL",
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_PTRACE",
    "PERFMON",
    "SYS_TIME",
    "DAC_READ_SEARCH",
)


class TestDangerousCapAddRule:
    def setup_method(self) -> None:
        self.rule = DangerousCapAddRule()

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
        assert meta.id == "CL-0011"
        assert meta.severity.value == "high"
        assert len(meta.references) > 0

    def test_detects_net_admin(self) -> None:
        findings = self._check("net_admin")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0011"
        assert findings[0].severity == Severity.HIGH
        assert "NET_ADMIN" in findings[0].message

    def test_detects_bpf(self) -> None:
        findings = self._check_cap("BPF")
        assert len(findings) == 1
        assert "BPF" in findings[0].message

    def test_detects_sys_boot(self) -> None:
        findings = self._check_cap("SYS_BOOT")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "SYS_BOOT" in findings[0].message

    def test_sys_boot_message_does_not_claim_kexec(self) -> None:
        """kexec_load returns EPERM even with SYS_BOOT held (verified)."""
        message = self._check_cap("SYS_BOOT")[0].message
        assert "reboot" in message
        assert "kexec_load is blocked" in message

    def test_stays_silent_on_the_other_tiers(self) -> None:
        for cap in OTHER_TIERS:
            assert self._check_cap(cap) == [], f"CL-0011 claimed {cap}"

    def test_ignores_dac_override(self) -> None:
        # DAC_OVERRIDE is one of Docker's 14 default capabilities, so adding it
        # back after cap_drop: [ALL] is not an escalation above the baseline —
        # the container holds it either way. Flagging it inverted the gate:
        # `cap_drop: [ALL]` + `cap_add: [DAC_OVERRIDE]` (one capability) failed
        # at --fail-on high while no cap_drop at all (fourteen, DAC_OVERRIDE
        # among them) passed. Same reasoning excludes MKNOD and SYS_CHROOT
        # (issue #492).
        assert self._check_cap("DAC_OVERRIDE") == []

    def test_detects_cap_prefixed_capability(self) -> None:
        # Docker treats `CAP_NET_ADMIN` == `NET_ADMIN` (issue #277 F2).
        findings = self._check_cap("CAP_NET_ADMIN")
        assert len(findings) == 1
        assert "CAP_NET_ADMIN" in findings[0].message

    def test_lowercase_normalized(self) -> None:
        findings = self._check_cap("net_admin")
        assert len(findings) == 1
        assert "NET_ADMIN" in findings[0].message

    def test_multiple_dangerous_yields_only_this_tier(self) -> None:
        # The fixture service names SYS_ADMIN, SYS_PTRACE and NET_ADMIN — one
        # per tier — so exactly one belongs to this rule.
        findings = self._check("multiple_dangerous")
        assert len(findings) == 1
        assert "NET_ADMIN" in findings[0].message

    def test_safe_caps_no_findings(self) -> None:
        assert self._check("safe_caps") == []

    def test_no_cap_add_no_findings(self) -> None:
        assert self._check("no_cap_add") == []

    def test_has_fix_guidance_and_references(self) -> None:
        findings = self._check("net_admin")
        assert findings[0].fix is not None
        assert "NET_ADMIN" in findings[0].fix
        assert len(findings[0].references) > 0

    def test_safe_drop_all_add_safe_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "safe_cap_hardened.yml")
        for service in ("drop_all_add_safe", "drop_all_lower_add_safe"):
            findings = list(
                self.rule.check(service, data["services"][service], data, lines)
            )
            assert findings == []
