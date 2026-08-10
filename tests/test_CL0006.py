"""Tests for CL-0006: No capability restrictions."""

from __future__ import annotations

from pathlib import Path

from compose_lint.parser import load_compose, loads
from compose_lint.rules.CL0006_cap_drop import CapDropRule

FIXTURES = Path(__file__).parent / "compose_files"


class TestCapDropRule:
    """Tests for capability restriction detection."""

    def setup_method(self) -> None:
        self.rule = CapDropRule()

    def test_detects_missing_cap_drop(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_cap_drop.yml")
        findings = list(
            self.rule.check("no_cap_drop", data["services"]["no_cap_drop"], data, lines)
        )
        assert len(findings) == 1
        assert findings[0].rule_id == "CL-0006"
        assert findings[0].severity.value == "medium"

    def test_detects_partial_cap_drop(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_cap_drop.yml")
        findings = list(
            self.rule.check(
                "partial_cap_drop",
                data["services"]["partial_cap_drop"],
                data,
                lines,
            )
        )
        assert len(findings) == 1

    def test_cap_drop_all_clean(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_cap_drop.yml")
        findings = list(
            self.rule.check(
                "cap_drop_all", data["services"]["cap_drop_all"], data, lines
            )
        )
        assert len(findings) == 0

    def test_cap_drop_all_case_insensitive(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_cap_drop.yml")
        findings = list(
            self.rule.check(
                "cap_drop_all_lower",
                data["services"]["cap_drop_all_lower"],
                data,
                lines,
            )
        )
        assert len(findings) == 0

    def test_has_fix_guidance(self) -> None:
        findings = list(self.rule.check("app", {"image": "nginx"}, {}, {}))
        assert findings[0].fix is not None
        assert "cap_drop" in findings[0].fix

    def test_has_references(self) -> None:
        findings = list(self.rule.check("app", {"image": "nginx"}, {}, {}))
        assert len(findings[0].references) > 0
        assert "owasp" in findings[0].references[0].lower()

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0006"
        assert meta.severity.value == "medium"
        assert len(meta.references) > 0

    def test_safe_drop_all_add_safe_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "safe_cap_hardened.yml")
        findings = list(
            self.rule.check(
                "drop_all_add_safe",
                data["services"]["drop_all_add_safe"],
                data,
                lines,
            )
        )
        assert len(findings) == 0

    def test_safe_drop_all_lower_add_safe_no_findings(self) -> None:
        data, lines = load_compose(FIXTURES / "safe_cap_hardened.yml")
        findings = list(
            self.rule.check(
                "drop_all_lower_add_safe",
                data["services"]["drop_all_lower_add_safe"],
                data,
                lines,
            )
        )
        assert len(findings) == 0

    def test_safe_drop_all_no_add_no_findings(self) -> None:
        # cap_drop: [ALL] with no cap_add — the most-hardened case, which must
        # not trip CL-0006. (Surfaced by the fixture-coverage check, #379.)
        data, lines = load_compose(FIXTURES / "safe_cap_hardened.yml")
        findings = list(
            self.rule.check(
                "drop_all_no_add",
                data["services"]["drop_all_no_add"],
                data,
                lines,
            )
        )
        assert len(findings) == 0


class TestCapDropNormalisation:
    """``cap_drop`` and ``cap_add`` must agree about a spelling.

    They did not: this rule upper-cased only, while ``_caps`` also trimmed and
    stripped the ``CAP_`` prefix, so ``cap_drop: [CAP_ALL]`` read as "did not
    drop all" while the same spelling on ``cap_add`` was normalised. Docker
    rejects both odd spellings, so neither reading shipped a wrong finding
    about a file that runs — but one answer is better than two.
    """

    def _findings(self, body: str) -> list:
        data, lines = loads(f"services:\n  app:\n    image: nginx:1.27\n{body}")
        return list(CapDropRule().check("app", data["services"]["app"], data, lines))

    def test_all_spellings_count_as_dropping_everything(self) -> None:
        for spelling in ("ALL", "all", "CAP_ALL", "cap_all", '"  ALL  "'):
            body = f"    cap_drop:\n      - {spelling}\n"
            assert self._findings(body) == [], spelling

    def test_a_partial_drop_still_fires(self) -> None:
        assert len(self._findings("    cap_drop:\n      - CHOWN\n")) == 1
