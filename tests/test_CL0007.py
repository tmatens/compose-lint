"""Tests for CL-0007: Filesystem not read-only."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose
from compose_lint.rules.CL0007_read_only import ReadOnlyFilesystemRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestReadOnlyFilesystemRule:
    """Tests for read-only filesystem detection."""

    def setup_method(self) -> None:
        self.rule = ReadOnlyFilesystemRule()

    def test_detects_missing_read_only(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_read_only.yml")
        findings = list(
            self.rule.check("writable", data["services"]["writable"], data, lines)
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0007"
        assert findings[0].severity.value == "warning"

    def test_detects_explicit_false(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_read_only.yml")
        findings = list(
            self.rule.check(
                "explicit_false", data["services"]["explicit_false"], data, lines
            )
        )
        assert len(findings) == 1

    def test_read_only_true_clean(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_read_only.yml")
        findings = list(
            self.rule.check(
                "read_only_true", data["services"]["read_only_true"], data, lines
            )
        )
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = list(self.rule.check("app", {"image": "nginx"}, {}, {}))
        assert findings[0].fix is not None
        assert "read_only: true" in findings[0].fix

    def test_has_references(self) -> None:
        findings = list(self.rule.check("app", {"image": "nginx"}, {}, {}))
        assert len(findings[0].references) > 0
        assert "owasp" in findings[0].references[0].lower()

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0007"
        assert meta.severity.value == "warning"
        assert len(meta.references) > 0
