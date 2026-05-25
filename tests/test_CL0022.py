"""Tests for CL-0022: tmpfs mount re-enables exec/suid/dev."""

from __future__ import annotations

from compose_lint.parser import loads
from compose_lint.rules.CL0022_tmpfs_insecure_options import (
    DOCKER_REF,
    TmpfsInsecureOptionsRule,
)


class TestTmpfsInsecureOptionsRule:
    """Detection of tmpfs mounts that remove a secure default."""

    def setup_method(self) -> None:
        self.rule = TmpfsInsecureOptionsRule()

    def _check(self, body: str) -> list:
        content = f"services:\n  a:\n    image: nginx:1.27\n{body}"
        data, lines = loads(content)
        return list(self.rule.check("a", data["services"]["a"], data, lines))

    def test_detects_exec(self) -> None:
        findings = self._check("    tmpfs:\n      - /tmp:exec\n")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0022"
        assert findings[0].severity.value == "low"
        assert "exec" in findings[0].message

    def test_detects_suid_and_dev(self) -> None:
        findings = self._check("    tmpfs:\n      - /tmp:suid\n      - /run:dev\n")
        assert len(findings) == 2

    def test_detects_multiple_on_one_entry(self) -> None:
        findings = self._check("    tmpfs:\n      - /tmp:exec,suid,dev\n")
        assert len(findings) == 1
        for tok in ("exec", "suid", "dev"):
            assert tok in findings[0].message

    def test_detects_scalar_form(self) -> None:
        findings = self._check("    tmpfs: /tmp:exec\n")
        assert len(findings) == 1

    def test_bare_tmpfs_is_clean(self) -> None:
        # No options => Docker applies noexec,nosuid,nodev; nothing to flag.
        assert self._check("    tmpfs:\n      - /tmp\n") == []

    def test_explicit_secure_flags_are_clean(self) -> None:
        assert self._check("    tmpfs:\n      - /tmp:noexec,nosuid,nodev\n") == []

    def test_noexec_token_not_confused_with_exec(self) -> None:
        # Whole-token match: 'noexec' must not be read as 'exec'.
        assert self._check("    tmpfs:\n      - /tmp:noexec\n") == []

    def test_benign_size_option_is_clean(self) -> None:
        assert self._check("    tmpfs:\n      - /run:size=64m\n") == []

    def test_exec_alongside_size_still_flags(self) -> None:
        findings = self._check("    tmpfs:\n      - /run:size=64m,exec\n")
        assert len(findings) == 1
        assert "exec" in findings[0].message

    def test_no_tmpfs_is_clean(self) -> None:
        assert self._check("    read_only: true\n") == []

    def test_points_at_the_entry_line(self) -> None:
        findings = self._check("    tmpfs:\n      - /tmp:exec\n")
        # Line 5: services(1) a(2) image(3) tmpfs(4) entry(5).
        assert findings[0].line == 5

    def test_metadata_and_references(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0022"
        assert meta.severity.value == "low"
        assert DOCKER_REF in meta.references
