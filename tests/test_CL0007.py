"""Tests for CL-0007: Filesystem not read-only."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from compose_lint.fix import apply_edits
from compose_lint.parser import load_compose
from compose_lint.rules.CL0007_read_only import ReadOnlyFilesystemRule

if TYPE_CHECKING:
    from compose_lint.models import TextEdit

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
        assert findings[0].severity.value == "medium"

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
        assert meta.severity.value == "medium"
        assert len(meta.references) > 0


class TestReadOnlyFix:
    """Tests for the CL-0007 auto-fix (ADR-014)."""

    def setup_method(self) -> None:
        self.rule = ReadOnlyFilesystemRule()

    def _fix(
        self, tmp_path: Path, content: str, service: str = "web"
    ) -> list[TextEdit] | None:
        path = tmp_path / "docker-compose.yml"
        path.write_text(content)
        data, lines = load_compose(path)
        findings = list(
            self.rule.check(service, data["services"][service], data, lines)
        )
        assert findings, "expected CL-0007 to fire"
        return self.rule.fix(findings[0], data, lines, content)

    def test_inserts_read_only_two_space_indent(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    image: nginx\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert apply_edits(content, edits) == (
            "services:\n  web:\n    read_only: true\n    image: nginx\n"
        )

    def test_inserts_read_only_four_space_indent(self, tmp_path: Path) -> None:
        content = "services:\n    web:\n        image: nginx\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert "        read_only: true\n" in apply_edits(content, edits)

    def test_edit_carries_caveat(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    image: nginx\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert edits[0].caveat is not None
        assert "read_only" in edits[0].caveat

    def test_preserves_comments_and_siblings(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:  # frontend\n"
            "    image: nginx  # pinned\n"
            "    ports:\n"
            "      - 8080:80\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        result = apply_edits(content, edits)
        assert "# frontend" in result
        assert "# pinned" in result
        assert "      - 8080:80\n" in result

    def test_fix_resolves_finding_and_is_idempotent(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    image: nginx\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        result = apply_edits(content, edits)
        # The fixed file must still parse and now declare read_only.
        fixed = tmp_path / "fixed.yml"
        fixed.write_text(result)
        data, lines = load_compose(fixed)
        assert data["services"]["web"]["read_only"] is True
        # Re-linting finds nothing, so re-running fix would be a no-op.
        findings = list(self.rule.check("web", data["services"]["web"], data, lines))
        assert findings == []

    def test_refuses_flow_style_service(self, tmp_path: Path) -> None:
        content = "services:\n  web: {image: nginx}\n"
        assert self._fix(tmp_path, content) is None

    def test_refuses_anchored_service(self, tmp_path: Path) -> None:
        content = "services:\n  web: &websvc\n    image: nginx\n"
        assert self._fix(tmp_path, content) is None

    def test_refuses_merge_key_service(self, tmp_path: Path) -> None:
        content = (
            "x-base: &base\n"
            "  image: nginx\n"
            "services:\n"
            "  web:\n"
            "    <<: *base\n"
            "    ports:\n"
            "      - 8080:80\n"
        )
        assert self._fix(tmp_path, content) is None

    def test_refuses_merge_key_behind_misindented_comment(self, tmp_path: Path) -> None:
        # A mis-indented comment before the merge key must not hide it, which
        # would let the fixer insert into an anchor-inheriting block and emit
        # invalid YAML (issue #261 H3).
        content = (
            "x-base: &base\n"
            "  restart: always\n"
            "services:\n"
            "  web:\n"
            "        # over-indented comment\n"
            "    <<: *base\n"
            "    image: nginx\n"
        )
        assert self._fix(tmp_path, content) is None

    def test_inserts_at_real_child_indent_past_leading_comment(
        self, tmp_path: Path
    ) -> None:
        # A leading comment must not set the insertion indent; read_only lands at
        # the real child's indent so the result still parses (issue #261).
        content = "services:\n  web:\n    # note\n    image: nginx\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        result = apply_edits(content, edits)
        assert result == (
            "services:\n  web:\n    read_only: true\n    # note\n    image: nginx\n"
        )
        fixed = tmp_path / "ok.yml"
        fixed.write_text(result)
        data, _ = load_compose(fixed)
        assert data["services"]["web"]["read_only"] is True

    def test_refuses_explicit_read_only_value(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    read_only: false\n    image: nginx\n"
        assert self._fix(tmp_path, content) is None
