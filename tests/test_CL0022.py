"""Tests for CL-0022: tmpfs mount not hardened."""

from __future__ import annotations

from compose_lint.fix import apply_edits
from compose_lint.parser import loads
from compose_lint.rules.CL0022_tmpfs_hardening import TmpfsHardeningRule


class TestTmpfsHardeningRule:
    """Detection of tmpfs mounts missing noexec/nosuid/nodev."""

    def setup_method(self) -> None:
        self.rule = TmpfsHardeningRule()

    def _check(self, body: str) -> list:
        content = f"services:\n  a:\n    image: nginx:1.27\n{body}"
        data, lines = loads(content)
        return list(self.rule.check("a", data["services"]["a"], data, lines))

    def test_detects_bare_list_entry(self) -> None:
        findings = self._check("    tmpfs:\n      - /tmp\n")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0022"
        assert findings[0].severity.value == "medium"
        assert "/tmp" in findings[0].message
        for flag in ("noexec", "nosuid", "nodev"):
            assert flag in findings[0].message

    def test_detects_scalar_form(self) -> None:
        findings = self._check("    tmpfs: /run\n")
        assert len(findings) == 1
        assert "/run" in findings[0].message

    def test_preserves_unrelated_options_but_still_flags(self) -> None:
        findings = self._check("    tmpfs:\n      - /run:size=64m\n")
        assert len(findings) == 1

    def test_partial_flags_still_fires_for_the_rest(self) -> None:
        findings = self._check("    tmpfs:\n      - /tmp:noexec\n")
        assert len(findings) == 1
        assert "nosuid" in findings[0].message
        assert "nodev" in findings[0].message
        assert "noexec" not in findings[0].message

    def test_fully_hardened_is_clean(self) -> None:
        findings = self._check("    tmpfs:\n      - /tmp:noexec,nosuid,nodev\n")
        assert findings == []

    def test_no_tmpfs_is_clean(self) -> None:
        assert self._check("    read_only: true\n") == []

    def test_long_form_volumes_tmpfs_out_of_scope(self) -> None:
        # The `volumes: [{type: tmpfs}]` form cannot express noexec/nosuid/nodev
        # through Compose, so it is intentionally not flagged.
        findings = self._check(
            "    volumes:\n      - type: tmpfs\n        target: /tmp\n"
        )
        assert findings == []

    def test_multiple_entries_each_flag(self) -> None:
        findings = self._check("    tmpfs:\n      - /tmp\n      - /run:nodev\n")
        assert len(findings) == 2

    def test_metadata_and_references(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0022"
        assert meta.severity.value == "medium"
        assert any("owasp" in r.lower() for r in meta.references)


class TestTmpfsHardeningFix:
    """The CL-0022 auto-fix appends the missing flags (ADR-014)."""

    def setup_method(self) -> None:
        self.rule = TmpfsHardeningRule()

    def _fix(self, content: str, want_path: str) -> list:
        data, lines = loads(content)
        findings = [
            f
            for f in self.rule.check("a", data["services"]["a"], data, lines)
            if f"'{want_path}'" in f.message
        ]
        assert findings, f"expected CL-0022 to fire for {want_path}"
        return self.rule.fix(findings[0], data, lines, content)

    def test_appends_all_flags_to_bare_list_entry(self) -> None:
        content = "services:\n  a:\n    image: nginx:1.27\n    tmpfs:\n      - /tmp\n"
        edits = self._fix(content, "/tmp")
        assert edits is not None
        assert "- /tmp:noexec,nosuid,nodev\n" in apply_edits(content, edits)

    def test_preserves_existing_options(self) -> None:
        content = (
            "services:\n  a:\n    image: nginx:1.27\n"
            "    tmpfs:\n      - /run:size=64m\n"
        )
        edits = self._fix(content, "/run")
        assert edits is not None
        assert "- /run:size=64m,noexec,nosuid,nodev\n" in apply_edits(content, edits)

    def test_fixes_scalar_form(self) -> None:
        content = "services:\n  a:\n    image: nginx:1.27\n    tmpfs: /var/cache\n"
        edits = self._fix(content, "/var/cache")
        assert edits is not None
        assert "tmpfs: /var/cache:noexec,nosuid,nodev\n" in apply_edits(content, edits)

    def test_only_appends_missing_flag(self) -> None:
        content = (
            "services:\n  a:\n    image: nginx:1.27\n    tmpfs:\n      - /tmp:noexec\n"
        )
        edits = self._fix(content, "/tmp")
        assert edits is not None
        assert "- /tmp:noexec,nosuid,nodev\n" in apply_edits(content, edits)

    def test_fix_is_idempotent(self) -> None:
        content = "services:\n  a:\n    image: nginx:1.27\n    tmpfs:\n      - /tmp\n"
        edits = self._fix(content, "/tmp")
        assert edits is not None
        fixed = apply_edits(content, edits)
        data, lines = loads(fixed)
        assert list(self.rule.check("a", data["services"]["a"], data, lines)) == []

    def test_edit_carries_caveat(self) -> None:
        content = "services:\n  a:\n    image: nginx:1.27\n    tmpfs:\n      - /tmp\n"
        edits = self._fix(content, "/tmp")
        assert edits is not None
        assert edits[0].caveat is not None
        assert "noexec" in edits[0].caveat

    def test_handles_quoted_value(self) -> None:
        content = 'services:\n  a:\n    image: nginx:1.27\n    tmpfs:\n      - "/tmp"\n'
        edits = self._fix(content, "/tmp")
        assert edits is not None
        # The replacement lands inside the quotes, keeping them intact.
        assert '"/tmp:noexec,nosuid,nodev"\n' in apply_edits(content, edits)

    def test_refuses_flow_style(self) -> None:
        content = "services:\n  a:\n    image: nginx:1.27\n    tmpfs: [/tmp]\n"
        assert self._fix(content, "/tmp") is None

    def test_refuses_interpolation(self) -> None:
        content = "services:\n  a:\n    image: nginx:1.27\n    tmpfs: ${TMP}\n"
        assert self._fix(content, "${TMP}") is None
