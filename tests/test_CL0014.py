"""Tests for CL-0014: Logging driver disabled."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from compose_lint.fix import apply_edits
from compose_lint.parser import load_compose
from compose_lint.rules.CL0014_logging_disabled import LoggingDisabledRule

if TYPE_CHECKING:
    from compose_lint.models import TextEdit

FIXTURES = Path(__file__).parent / "compose_files"


class TestLoggingDisabledRule:
    """Tests for logging driver disabled detection."""

    def setup_method(self) -> None:
        self.rule = LoggingDisabledRule()

    def _check(self, service_name: str) -> list:
        data, lines = load_compose(FIXTURES / "insecure_logging.yml")
        return list(
            self.rule.check(service_name, data["services"][service_name], data, lines)
        )

    def test_detects_driver_none(self) -> None:
        findings = self._check("logging_none")
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0014"
        assert "none" in findings[0].message.lower()

    def test_detects_driver_none_case_insensitive(self) -> None:
        findings = self._check("logging_none_uppercase")
        assert len(findings) == 1

    def test_json_file_no_findings(self) -> None:
        findings = self._check("logging_json")
        assert len(findings) == 0

    def test_syslog_no_findings(self) -> None:
        findings = self._check("logging_syslog")
        assert len(findings) == 0

    def test_no_logging_config_no_findings(self) -> None:
        findings = self._check("no_logging_config")
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = self._check("logging_none")
        assert findings[0].fix is not None
        assert "json-file" in findings[0].fix

    def test_has_references(self) -> None:
        findings = self._check("logging_none")
        assert len(findings[0].references) > 0

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0014"
        assert meta.severity.value == "medium"


class TestLoggingDisabledFix:
    """Tests for the CL-0014 deletion fix (ADR-014)."""

    def setup_method(self) -> None:
        self.rule = LoggingDisabledRule()

    def _fix(
        self, tmp_path: Path, content: str, service: str = "web"
    ) -> list[TextEdit] | None:
        path = tmp_path / "docker-compose.yml"
        path.write_text(content)
        data, lines = load_compose(path)
        findings = list(
            self.rule.check(service, data["services"][service], data, lines)
        )
        assert findings, "expected CL-0014 to fire"
        return self.rule.fix(findings[0], data, lines, content)

    def test_collapses_logging_block_when_driver_is_sole_key(
        self, tmp_path: Path
    ) -> None:
        content = (
            "services:\n  web:\n    image: nginx\n    logging:\n      driver: none\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        # The whole logging block is dropped, not left as an empty `logging:`.
        assert apply_edits(content, edits) == ("services:\n  web:\n    image: nginx\n")

    def test_refuses_when_logging_has_other_keys(self, tmp_path: Path) -> None:
        # Deleting only the driver would strand `options:` — a partial block.
        content = (
            "services:\n"
            "  web:\n"
            "    logging:\n"
            "      driver: none\n"
            "      options:\n"
            "        max-size: 10m\n"
        )
        assert self._fix(tmp_path, content) is None

    def test_edit_carries_caveat(self, tmp_path: Path) -> None:
        content = (
            "services:\n  web:\n    image: nginx\n    logging:\n      driver: none\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        assert edits[0].caveat is not None
        assert "logging" in edits[0].caveat.lower()

    def test_refuses_when_block_is_services_sole_key(self, tmp_path: Path) -> None:
        # Deleting the logging block would leave `web:` with a null body, which
        # no longer parses as Compose (issue #261 H1). Refuse instead.
        content = "services:\n  web:\n    logging:\n      driver: none\n"
        assert self._fix(tmp_path, content) is None

    def test_fix_resolves_finding_and_is_idempotent(self, tmp_path: Path) -> None:
        content = (
            "services:\n  web:\n    image: nginx\n    logging:\n      driver: none\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        fixed = tmp_path / "fixed.yml"
        fixed.write_text(apply_edits(content, edits))
        data, lines = load_compose(fixed)
        assert "logging" not in data["services"]["web"]
        findings = list(self.rule.check("web", data["services"]["web"], data, lines))
        assert findings == []

    def test_preserves_comments_and_siblings(self, tmp_path: Path) -> None:
        content = (
            "services:\n"
            "  web:  # frontend\n"
            "    image: nginx  # pinned\n"
            "    logging:\n"
            "      driver: none\n"
            "  db:\n"
            "    image: postgres\n"
        )
        edits = self._fix(tmp_path, content)
        assert edits is not None
        result = apply_edits(content, edits)
        assert "# frontend" in result
        assert "# pinned" in result
        assert "  db:\n    image: postgres\n" in result

    def test_refuses_flow_style_logging(self, tmp_path: Path) -> None:
        content = "services:\n  web:\n    logging: {driver: none}\n"
        assert self._fix(tmp_path, content) is None

    def test_refuses_anchored_service(self, tmp_path: Path) -> None:
        content = "services:\n  web: &websvc\n    logging:\n      driver: none\n"
        assert self._fix(tmp_path, content) is None

    def test_refuses_merge_key_service(self, tmp_path: Path) -> None:
        content = (
            "x-base: &base\n"
            "  image: nginx\n"
            "services:\n"
            "  web:\n"
            "    <<: *base\n"
            "    logging:\n"
            "      driver: none\n"
        )
        assert self._fix(tmp_path, content) is None
