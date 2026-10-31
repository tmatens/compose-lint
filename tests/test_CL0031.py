"""Tests for CL-0031: Engine API delegated with registry credentials."""

from __future__ import annotations

import json
from pathlib import Path

from compose_lint.engine import run_rules
from compose_lint.parser import load_compose, loads
from compose_lint.rules.CL0031_api_socket import ApiSocketRule, delegates_api_socket
from tests.test_cli import run_cli

FIXTURES = Path(__file__).parent / "compose_files"


class TestApiSocketRule:
    """Tests for `use_api_socket: true` detection."""

    def setup_method(self) -> None:
        self.rule = ApiSocketRule()

    def _check(self, content: str, service: str = "a") -> list:
        data, lines = loads(content)
        return list(self.rule.check(service, data["services"][service], data, lines))

    def test_detects_the_key(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_api_socket.yml")
        findings = list(
            self.rule.check("gateway", data["services"]["gateway"], data, lines)
        )
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "CL-0031"
        assert f.severity.value == "critical"
        assert f.evidence == "use_api_socket"
        assert f.line == 4  # the key's own line, not the service's
        assert "registry logins" in f.message
        assert "host's Docker socket" in f.message

    def test_opted_out_is_clean(self) -> None:
        # The hardened-but-unusual negative: the key spelled out as false.
        data, lines = load_compose(FIXTURES / "insecure_api_socket.yml")
        findings = list(
            self.rule.check("opted_out", data["services"]["opted_out"], data, lines)
        )
        assert findings == []

    def test_no_key_is_clean(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_api_socket.yml")
        findings = list(
            self.rule.check("clean", data["services"]["clean"], data, lines)
        )
        assert findings == []

    def test_quoted_string_is_not_graded(self) -> None:
        # Compose refuses `use_api_socket: "true"` ("must be a boolean"), so
        # the file never deploys. Unlike `privileged`, no coercion applies.
        content = 'services:\n  a:\n    image: x:1\n    use_api_socket: "true"\n'
        assert self._check(content) == []

    def test_interpolated_default_is_not_graded(self) -> None:
        # The parser normalises `${X:-true}` to the string "true"; Compose
        # refuses the key either way, so there is nothing to grade.
        content = "services:\n  a:\n    image: x:1\n    use_api_socket: ${X:-true}\n"
        assert self._check(content) == []

    def test_bare_reference_is_not_graded(self) -> None:
        content = "services:\n  a:\n    image: x:1\n    use_api_socket: ${X}\n"
        assert self._check(content) == []

    def test_yaml_1_1_spellings_are_graded_as_true(self) -> None:
        # The parser keeps YAML 1.1 booleans, so `yes` and `on` arrive as True.
        # Compose refuses both ("must be a boolean", measured on v5.0.0), so
        # the file does not deploy until spelled `true`, which is the graded
        # form; the parser cannot tell the spellings apart, and the page says
        # so.
        for spelling in ("yes", "on"):
            content = (
                f"services:\n  a:\n    image: x:1\n    use_api_socket: {spelling}\n"
            )
            assert len(self._check(content)) == 1, spelling

    def test_fires_once_per_service(self) -> None:
        content = "services:\n  a:\n    image: x:1\n    use_api_socket: true\n"
        assert len(self._check(content)) == 1

    def test_has_fix_guidance_naming_the_sibling_rule(self) -> None:
        content = "services:\n  a:\n    image: x:1\n    use_api_socket: true\n"
        fix = self._check(content)[0].fix
        assert fix is not None
        assert "CL-0001" in fix
        assert "deploy identity" in fix

    def test_has_references(self) -> None:
        refs = self.rule.metadata.references
        assert len(refs) >= 2
        assert "owasp" in refs[0].lower()
        assert any("use_api_socket" in r for r in refs)

    def test_metadata(self) -> None:
        meta = self.rule.metadata
        assert meta.id == "CL-0031"
        assert meta.severity.value == "critical"


class TestTwoGrantsAreTwoFindings:
    """The key beside a `volumes:` socket mount is both rules, not one."""

    def test_both_rules_fire_on_the_same_service(self) -> None:
        data, lines = load_compose(FIXTURES / "insecure_api_socket.yml")
        by_service: dict[str, set[str]] = {}
        for f in run_rules(data, lines):
            by_service.setdefault(f.service, set()).add(f.rule_id)
        assert {"CL-0001", "CL-0031"} <= by_service["both"]
        assert "CL-0031" in by_service["gateway"]
        assert "CL-0001" not in by_service["gateway"]
        assert "CL-0031" not in by_service.get("opted_out", set())


class TestOverrideCancelsTheBase:
    """`use_api_socket: false` in compose.override.yml cancels a base `true`.

    Compose merges the override before it reads the key, and so does the
    linter; the finding must follow the merged value, not the base file's.
    """

    def test_override_false_removes_the_finding(self, tmp_path: Path) -> None:
        (tmp_path / "compose.yml").write_text(
            "services:\n  a:\n    image: x:1\n    use_api_socket: true\n"
        )
        (tmp_path / "compose.override.yml").write_text(
            "services:\n  a:\n    use_api_socket: false\n"
        )
        result = run_cli("check", "--format", "json", "--fail-on", "low", cwd=tmp_path)
        rule_ids = {f["rule_id"] for f in json.loads(result.stdout)["findings"]}
        assert "CL-0031" not in rule_ids

    def test_override_true_adds_the_finding(self, tmp_path: Path) -> None:
        (tmp_path / "compose.yml").write_text("services:\n  a:\n    image: x:1\n")
        (tmp_path / "compose.override.yml").write_text(
            "services:\n  a:\n    use_api_socket: true\n"
        )
        result = run_cli("check", "--format", "json", "--fail-on", "low", cwd=tmp_path)
        rule_ids = {f["rule_id"] for f in json.loads(result.stdout)["findings"]}
        assert "CL-0031" in rule_ids


class TestSharedPredicate:
    """The CL-0007 fixer reads the same predicate, so the two cannot drift."""

    def test_predicate_is_the_literal_boolean_only(self) -> None:
        assert delegates_api_socket({"use_api_socket": True})
        assert not delegates_api_socket({"use_api_socket": "true"})
        assert not delegates_api_socket({"use_api_socket": False})
        assert not delegates_api_socket({})
