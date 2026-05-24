"""Tests for CL-0003: Privilege escalation not blocked."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from compose_lint.fix import apply_edits
from compose_lint.parser import load_compose, loads
from compose_lint.rules.CL0003_no_new_privileges import NoNewPrivilegesRule

if TYPE_CHECKING:
    from compose_lint.models import TextEdit

FIXTURES = Path(__file__).parent / "compose_files"


class TestNoNewPrivilegesRule:
    """Tests for no-new-privileges detection."""

    def setup_method(self) -> None:
        self.rule = NoNewPrivilegesRule()

    def test_detects_missing_security_opt(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_no_new_priv.yml")
        findings = list(
            self.rule.check("missing", data["services"]["missing"], data, lines)
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0003"
        assert findings[0].severity.value == "medium"

    def test_detects_empty_security_opt(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_no_new_priv.yml")
        findings = list(
            self.rule.check(
                "empty_security_opt",
                data["services"]["empty_security_opt"],
                data,
                lines,
            )
        )
        assert len(findings) == 1

    def test_detects_other_opt_without_no_new_priv(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_no_new_priv.yml")
        findings = list(
            self.rule.check(
                "has_other_opt", data["services"]["has_other_opt"], data, lines
            )
        )
        assert len(findings) == 1

    def test_secure_service_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_no_new_priv.yml")
        findings = list(
            self.rule.check("secure", data["services"]["secure"], data, lines)
        )
        assert len(findings) == 0

    def test_safe_short_form_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "safe_no_new_priv_short.yml")
        findings = list(
            self.rule.check("short_form", data["services"]["short_form"], data, lines)
        )
        assert len(findings) == 0

    def test_equals_separator_counts_as_hardened(self) -> None:
        # Docker accepts `no-new-privileges=true` as well as the colon form, so a
        # service hardened with the `=` form must not be flagged (#277 P1).
        data, lines = loads(
            "services:\n"
            "  a:\n"
            "    image: nginx:1.27\n"
            "    security_opt:\n"
            "      - no-new-privileges=true\n"
        )
        findings = list(self.rule.check("a", data["services"]["a"], data, lines))
        assert findings == []

    def test_safe_short_form_with_others_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "safe_no_new_priv_short.yml")
        findings = list(
            self.rule.check(
                "short_form_with_others",
                data["services"]["short_form_with_others"],
                data,
                lines,
            )
        )
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = list(self.rule.check("app", {"image": "nginx"}, {}, {}))
        assert findings[0].fix is not None
        assert "no-new-privileges" in findings[0].fix

    def test_has_references(self) -> None:
        assert len(self.rule.metadata.references) > 0
        assert "owasp" in self.rule.metadata.references[0].lower()


class TestNoNewPrivilegesFix:
    """Tests for the CL-0003 append/create fix (ADR-014)."""

    def setup_method(self) -> None:
        self.rule = NoNewPrivilegesRule()

    def _fix(
        self, tmp_path: Path, content: str, service: str = "web"
    ) -> list[TextEdit] | None:
        path = tmp_path / "docker-compose.yml"
        path.write_text(content)
        data, lines = load_compose(path)
        findings = list(
            self.rule.check(service, data["services"][service], data, lines)
        )
        assert findings, "expected CL-0003 to fire"
        return self.rule.fix(findings[0], data, lines, content)

    def test_creates_security_opt_when_absent(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    image: nginx\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert apply_edits(content, edits) == (
            "services:\n"
            "  web:\n"
            "    security_opt:\n"
            "      - no-new-privileges:true\n"
            "    image: nginx\n"
        )

    def test_create_uses_existing_indentation_step(self, tmp_path: Path) -> None:
        content = "services:\n    web:\n        image: nginx\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        result = apply_edits(content, edits)
        assert "        security_opt:\n" in result
        assert "            - no-new-privileges:true\n" in result

    def test_appends_to_existing_list(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    image: nginx\n"
            "    security_opt:\n"
            "      - label:type:svirt_apache_t\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert apply_edits(content, edits) == (
            "services:\n"
            "  web:\n"
            "    image: nginx\n"
            "    security_opt:\n"
            "      - label:type:svirt_apache_t\n"
            "      - no-new-privileges:true\n"
        )

    def test_no_caveat_hardening_only(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    image: nginx\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert all(edit.caveat is None for edit in edits)

    def test_append_to_final_line_without_trailing_newline(
        self, tmp_path: Path
    ) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    security_opt:\n"
            "      - label:type:svirt_apache_t"  # no trailing newline
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        result = apply_edits(content, edits)
        assert result.endswith(
            "      - label:type:svirt_apache_t\n      - no-new-privileges:true\n"
        )

    def test_preserves_comments_and_siblings(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:  # frontend\n"
            "    image: nginx  # pinned\n"
            "    security_opt:\n"
            "      - label:type:svirt_apache_t  # keep\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        result = apply_edits(content, edits)
        assert "# frontend" in result
        assert "# pinned" in result
        assert "# keep" in result

    def test_fix_resolves_finding_and_is_idempotent(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    image: nginx\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        fixed = tmp_path / "fixed.yml"
        fixed.write_text(apply_edits(content, edits))
        data, lines = load_compose(fixed)
        assert "no-new-privileges:true" in data["services"]["web"]["security_opt"]
        findings = list(self.rule.check("web", data["services"]["web"], data, lines))
        assert findings == []

    def test_refuses_flow_style_security_opt(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    security_opt: [label:disable]\n"
        assert self._fix(tmp_path, content) is None

    def test_refuses_existing_no_new_privileges_false(self, tmp_path: Path) -> None:
        content = (
            "services:\n  web:\n    security_opt:\n      - no-new-privileges:false\n"
        )
        assert self._fix(tmp_path, content) is None

    def test_refuses_all_disabled_security_opt(self, tmp_path: Path) -> None:
        # Every entry is a profile-disable CL-0009 will remove. Appending a
        # survivor now would let a second pass delete those entries (CL-0009 then
        # sees a legit entry) — non-idempotent. Refuse; the block is left as-is.
        content = (
            "services:\n"
            "  web:\n"
            "    security_opt:\n"
            "      - seccomp:unconfined\n"
            "      - apparmor:unconfined\n"
        )
        assert self._fix(tmp_path, content) is None

    def test_anchor_child_service_refused(self, tmp_path: Path) -> None:
        # Service anchored by a lone `&anchor` first child: inserting before it
        # would re-anchor the wrong node.
        content = "services:\n  web:\n    &websvc\n    image: nginx\n"
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
            "    image: nginx\n"
        )
        assert self._fix(tmp_path, content) is None

    def test_refuses_both_sides_of_extends(self, tmp_path: Path) -> None:
        # Docker concatenates security_opt across an extends merge, so adding the
        # entry to either side can duplicate it post-merge (issue #277 C1): a base
        # that adds it collides with one the child already carries (or that a
        # sibling fixer adds), and the child collides with the inherited copy.
        # Both sides refuse; the human resolves the chain.
        content = (
            "services:\n"
            "  base:\n"
            "    image: nginx\n"
            "  child:\n"
            "    extends: base\n"
            "    image: nginx\n"
        )
        assert self._fix(tmp_path, content, service="child") is None
        # The base is an extends target, so it is no longer auto-fixed either.
        assert self._fix(tmp_path, content, service="base") is None

    def test_fixes_service_with_no_extends_relation(self, tmp_path: Path) -> None:
        # A plain service in a file that happens to use extends elsewhere is still
        # fixed: only the base and the extending child step aside.
        content = (
            "services:\n"
            "  base:\n"
            "    image: nginx\n"
            "  child:\n"
            "    extends: base\n"
            "    image: nginx\n"
            "  standalone:\n"
            "    image: nginx\n"
        )
        assert self._fix(tmp_path, content, service="standalone") is not None
