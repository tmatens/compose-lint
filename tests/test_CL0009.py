"""Tests for CL-0009: Security profile disabled."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
from compose_lint.rules.CL0009_security_profile import SecurityProfileRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestSecurityProfileRule:
    """Tests for disabled security profile detection."""

    def setup_method(self) -> None:
        self.rule = SecurityProfileRule()

    def test_detects_seccomp_unconfined(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_security_profile.yml")
        findings = list(
            self.rule.check(
                "seccomp_unconfined",
                data["services"]["seccomp_unconfined"],
                data,
                lines,
            )
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0009"
        assert "seccomp" in findings[0].message

    def test_detects_apparmor_unconfined(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_security_profile.yml")
        findings = list(
            self.rule.check(
                "apparmor_unconfined",
                data["services"]["apparmor_unconfined"],
                data,
                lines,
            )
        )
        assert len(findings) == 1
        assert "apparmor" in findings[0].message

    def test_detects_both_unconfined(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_security_profile.yml")
        findings = list(
            self.rule.check(
                "both_unconfined",
                data["services"]["both_unconfined"],
                data,
                lines,
            )
        )
        assert len(findings) == 2

    def test_custom_seccomp_clean(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_security_profile.yml")
        findings = list(
            self.rule.check(
                "custom_seccomp",
                data["services"]["custom_seccomp"],
                data,
                lines,
            )
        )
        assert len(findings) == 0

    def test_no_new_privs_only_clean(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_security_profile.yml")
        findings = list(
            self.rule.check(
                "no_new_privs_only",
                data["services"]["no_new_privs_only"],
                data,
                lines,
            )
        )
        assert len(findings) == 0

    def test_no_security_opt_clean(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_security_profile.yml")
        findings = list(
            self.rule.check(
                "no_security_opt",
                data["services"]["no_security_opt"],
                data,
                lines,
            )
        )
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_security_profile.yml")
        findings = list(
            self.rule.check(
                "seccomp_unconfined",
                data["services"]["seccomp_unconfined"],
                data,
                lines,
            )
        )
        assert findings[0].fix is not None
        assert "seccomp" in findings[0].fix

    def test_has_references(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_security_profile.yml")
        findings = list(
            self.rule.check(
                "seccomp_unconfined",
                data["services"]["seccomp_unconfined"],
                data,
                lines,
            )
        )
        assert len(findings[0].references) > 0
        assert "owasp" in findings[0].references[0].lower()

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0009"
        assert meta.severity.value == "high"
        assert len(meta.references) > 0

    def test_detects_selinux_label_disable(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_security_profile.yml")
        findings = list(
            self.rule.check(
                "selinux_disabled",
                data["services"]["selinux_disabled"],
                data,
                lines,
            )
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0009"
        assert "SELinux" in findings[0].message
        assert "label:disable" in findings[0].message

    def test_detects_all_three_profiles(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_security_profile.yml")
        findings = list(
            self.rule.check(
                "all_three_disabled",
                data["services"]["all_three_disabled"],
                data,
                lines,
            )
        )
        assert len(findings) == 3

    def test_selinux_label_user_no_finding(self) -> None:
        """label:user:... is a label override, not a disable — don't fire."""
        data, lines = load_compose(FIXTURES / "insecure_security_profile.yml")
        findings = list(
            self.rule.check(
                "selinux_label_user",
                data["services"]["selinux_label_user"],
                data,
                lines,
            )
        )
        assert len(findings) == 0
