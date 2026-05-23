"""Tests for CL-0015: Healthcheck explicitly disabled."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from compose_lint.fix import apply_edits
from compose_lint.parser import load_compose
from compose_lint.rules.CL0015_healthcheck_disabled import HealthcheckDisabledRule

if TYPE_CHECKING:
    from compose_lint.models import TextEdit

FIXTURES = Path(__file__).parent / "compose_files"


class TestHealthcheckDisabledRule:
    """Tests for healthcheck disabled detection."""

    def setup_method(self) -> None:
        self.rule = HealthcheckDisabledRule()

    def _check(self, service_name: str) -> list:
        data, lines = load_compose(FIXTURES / "insecure_healthcheck.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def test_detects_disabled(self) -> None:
        findings = self._check("disabled")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0015"
        assert "disabled" in findings[0].message.lower()

    def test_configured_no_findings(self) -> None:
        findings = self._check("configured")
        assert len(findings) == 0

    def test_no_healthcheck_no_findings(self) -> None:
        findings = self._check("no_healthcheck")
        assert len(findings) == 0

    def test_disable_false_no_findings(self) -> None:
        findings = self._check("disable_false")
        assert len(findings) == 0

    def test_detects_test_none_list(self) -> None:
        findings = self._check("disabled_via_test_list")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0015"
        assert 'test: ["NONE"]' in findings[0].message

    def test_detects_test_none_string(self) -> None:
        findings = self._check("disabled_via_test_string")
        assert len(findings) == 1
        assert 'test: ["NONE"]' in findings[0].message

    def test_test_none_lowercase_no_findings(self) -> None:
        findings = self._check("disabled_via_test_lowercase")
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = self._check("disabled")
        assert findings[0].fix is not None
        assert "healthcheck" in findings[0].fix.lower()

    def test_has_references(self) -> None:
        findings = self._check("disabled")
        assert len(findings[0].references) == 2

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0015"
        assert meta.severity.value == "low"

    def test_safe_cmd_shell_list_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "safe_healthcheck_cmd_shell.yml")
        findings = list(
            self.rule.check("cmd_shell", data["services"]["cmd_shell"], data, lines)
        )
        assert len(findings) == 0

    def test_safe_cmd_shell_string_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "safe_healthcheck_cmd_shell.yml")
        findings = list(
            self.rule.check(
                "cmd_shell_string",
                data["services"]["cmd_shell_string"],
                data,
                lines,
            )
        )
        assert len(findings) == 0


class TestHealthcheckDisabledFix:
    """Tests for the CL-0015 deletion fix (ADR-014)."""

    def setup_method(self) -> None:
        self.rule = HealthcheckDisabledRule()

    def _fix(
        self, tmp_path: Path, content: str, service: str = "web"
    ) -> list[TextEdit] | None:
        path = tmp_path / "docker-compose.yml"
        path.write_text(content)
        data, lines = load_compose(path)
        findings = list(
            self.rule.check(service, data["services"][service], data, lines)
        )
        assert findings, "expected CL-0015 to fire"
        return self.rule.fix(findings[0], data, lines, content)

    def test_collapses_block_for_disable_true(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    image: nginx\n"
            "    healthcheck:\n"
            "      disable: true\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert apply_edits(content, edits) == ("services:\n  web:\n    image: nginx\n")

    def test_collapses_block_for_test_none(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    image: nginx\n"
            "    healthcheck:\n"
            '      test: ["NONE"]\n'
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert apply_edits(content, edits) == ("services:\n  web:\n    image: nginx\n")

    def test_refuses_when_healthcheck_has_other_keys(self, tmp_path: Path) -> None:
        # Deleting `test: ["NONE"]` would strand `interval:` — a partial block.
        content = (
            "services:\n"
            "  web:\n"
            "    healthcheck:\n"
            '      test: ["NONE"]\n'
            "      interval: 30s\n"
        )
        assert self._fix(tmp_path, content) is None

    def test_edit_carries_caveat(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    healthcheck:\n      disable: true\n"
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert edits[0].caveat is not None
        assert "healthcheck" in edits[0].caveat.lower()

    def test_fix_resolves_finding_and_is_idempotent(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:\n"
            "    image: nginx\n"
            "    healthcheck:\n"
            "      disable: true\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        fixed = tmp_path / "fixed.yml"
        fixed.write_text(apply_edits(content, edits))
        data, lines = load_compose(fixed)
        assert "healthcheck" not in data["services"]["web"]
        findings = list(self.rule.check("web", data["services"]["web"], data, lines))
        assert findings == []

    def test_refuses_flow_style_healthcheck(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    healthcheck: {disable: true}\n"
        assert self._fix(tmp_path, content) is None

    def test_refuses_anchored_service(self, tmp_path: Path) -> None:
        content = "services:\n  web: &websvc\n    healthcheck:\n      disable: true\n"
        assert self._fix(tmp_path, content) is None

    def test_refuses_merge_key_service(self, tmp_path: Path) -> None:
        content = (
            "x-base: &base\n"
            "  image: nginx\n"
            "services:\n"
            "  web:\n"
            "    <<: *base\n"
            "    healthcheck:\n"
            "      disable: true\n"
        )
        assert self._fix(tmp_path, content) is None
