"""Tests for CL-0009: Security profile disabled."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from compose_lint.fix import apply_edits
from compose_lint.parser import load_compose
from compose_lint.rules.CL0009_security_profile import SecurityProfileRule

if TYPE_CHECKING:
    from compose_lint.models import TextEdit

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


class TestSecurityProfileFix:
    """Tests for the CL-0009 deletion fix (ADR-014)."""

    def setup_method(self) -> None:
        self.rule = SecurityProfileRule()

    def _fix(
        self, tmp_path: Path, content: str, service: str = "web"
    ) -> list[TextEdit] | None:
        path = tmp_path / "docker-compose.yml"
        path.write_text(content)
        data, lines = load_compose(path)
        findings = list(
            self.rule.check(service, data["services"][service], data, lines)
        )
        assert findings, "expected CL-0009 to fire"
        return self.rule.fix(findings[0], data, lines, content)

    def test_refuses_sole_offending_entry(self, tmp_path: Path) -> None:
        # A lone unconfined entry would empty the block. CL-0003 fires on the
        # same service (no no-new-privileges) and would recreate security_opt on
        # a second pass, so collapsing here is non-idempotent; the idempotent
        # end state needs a cross-rule merge the per-finding fixers can't do.
        # Refuse and leave it for manual remediation (ADR-014).
        content = (
            "services:\n"
            "  web:\n"
            "    image: nginx\n"
            "    security_opt:\n"
            "      - seccomp:unconfined\n"
        )
        assert self._fix(tmp_path, content) is None

    def test_removes_only_offending_item_when_legit_remains(
        self, tmp_path: Path
    ) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    image: nginx\n"
            "    security_opt:\n"
            "      - seccomp:unconfined\n"
            "      - no-new-privileges:true\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        result = apply_edits(content, edits)
        assert "seccomp:unconfined" not in result
        assert "no-new-privileges:true" in result
        assert "security_opt:" in result

    def test_refuses_when_all_entries_offending_but_many(self, tmp_path: Path) -> None:
        # Collapsing this correctly needs the two per-finding fixers to
        # coordinate, which they can't — refuse rather than empty the block.
        content = (
            "services:\n"
            "  web:\n"
            "    image: nginx\n"
            "    security_opt:\n"
            "      - seccomp:unconfined\n"
            "      - apparmor:unconfined\n"
        )
        assert self._fix(tmp_path, content) is None

    def test_edit_carries_caveat(self, tmp_path: Path) -> None:
        content = (
            "services:\n  web:\n    security_opt:\n"
            "      - seccomp:unconfined\n      - no-new-privileges:true\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert edits[0].caveat is not None
        assert "seccomp" in edits[0].caveat.lower()

    def test_fix_resolves_finding_and_is_idempotent(self, tmp_path: Path) -> None:
        # A legit entry survives, so CL-0009 removes only the offending item and
        # the block stays non-empty.
        content = (
            "services:\n"
            "  web:\n"
            "    image: nginx\n"
            "    security_opt:\n"
            "      - seccomp:unconfined\n"
            "      - no-new-privileges:true\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        fixed = tmp_path / "fixed.yml"
        fixed.write_text(apply_edits(content, edits))
        data, lines = load_compose(fixed)
        assert data["services"]["web"]["security_opt"] == ["no-new-privileges:true"]
        findings = list(self.rule.check("web", data["services"]["web"], data, lines))
        assert findings == []

    def test_preserves_comments_and_siblings(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:  # frontend\n"
            "    image: nginx  # pinned\n"
            "    security_opt:\n"
            "      - seccomp:unconfined\n"
            "      - no-new-privileges:true  # keep\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        result = apply_edits(content, edits)
        assert "# frontend" in result
        assert "# pinned" in result
        assert "# keep" in result

    def test_refuses_flow_style_list(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    security_opt: [seccomp:unconfined]\n"
        assert self._fix(tmp_path, content) is None

    def test_refuses_anchored_service(self, tmp_path: Path) -> None:
        content = (
            "services:\n  web: &websvc\n    security_opt:\n      - seccomp:unconfined\n"
        )
        assert self._fix(tmp_path, content) is None

    def test_refuses_merge_key_service(self, tmp_path: Path) -> None:
        content = (
            "x-base: &base\n"
            "  image: nginx\n"
            "services:\n"
            "  web:\n"
            "    <<: *base\n"
            "    security_opt:\n"
            "      - seccomp:unconfined\n"
        )
        assert self._fix(tmp_path, content) is None
