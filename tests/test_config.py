"""Tests for config file loading."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from compose_lint.config import ConfigError, load_config
from compose_lint.models import Severity


class TestLoadConfig:
    """Tests for load_config function."""

    def test_no_config_file_returns_defaults(self, tmp_path: Path) -> None:
        import os

        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            disabled, overrides, _excluded = load_config()
            assert disabled == {}
            assert overrides == {}
        finally:
            os.chdir(old_cwd)

    def test_disable_rule(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0001:\n    enabled: false\n")
        disabled, overrides, _excluded = load_config(config)
        assert "CL-0001" in disabled

    def test_severity_override(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0005:\n    severity: high\n")
        disabled, overrides, _excluded = load_config(config)
        assert overrides["CL-0005"] == Severity.HIGH

    def test_multiple_rules(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text(
            "rules:\n"
            "  CL-0001:\n"
            "    enabled: false\n"
            "  CL-0003:\n"
            "    severity: high\n"
            "  CL-0005:\n"
            "    enabled: false\n"
        )
        disabled, overrides, _excluded = load_config(config)
        assert set(disabled) == {"CL-0001", "CL-0005"}
        assert overrides["CL-0003"] == Severity.HIGH

    def test_disable_rule_with_reason(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text(
            "rules:\n"
            "  CL-0001:\n"
            "    enabled: false\n"
            '    reason: "SEC-1234 approved by J. Smith"\n'
        )
        disabled, overrides, _excluded = load_config(config)
        assert "CL-0001" in disabled
        assert disabled["CL-0001"] == "SEC-1234 approved by J. Smith"

    def test_disable_rule_without_reason(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0001:\n    enabled: false\n")
        disabled, overrides, _excluded = load_config(config)
        assert "CL-0001" in disabled
        assert disabled["CL-0001"] is None

    def test_explicit_path_not_found(self) -> None:
        with pytest.raises(ConfigError, match="not found"):
            load_config("/nonexistent/.compose-lint.yml")

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules: [invalid: yaml: {")
        with pytest.raises(ConfigError, match="Invalid YAML"):
            load_config(config)

    def test_invalid_severity(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0001:\n    severity: catastrophic\n")
        with pytest.raises(ConfigError, match="Invalid severity"):
            load_config(config)

    def test_empty_config(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("")
        disabled, overrides, _excluded = load_config(config)
        assert disabled == {}
        assert overrides == {}

    def test_config_not_mapping(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("- list\n- items\n")
        with pytest.raises(ConfigError, match="must be a YAML mapping"):
            load_config(config)

    def test_rules_not_mapping(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  - CL-0001\n")
        with pytest.raises(ConfigError, match="'rules' must be a mapping"):
            load_config(config)


class TestConfigValidation:
    """Validation of silent config misconfiguration (issue #279 G1/G2)."""

    def test_unknown_rule_id_warns(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-9999:\n    enabled: false\n")
        load_config(config)
        err = capsys.readouterr().err
        assert "unknown rule id 'CL-9999'" in err

    def test_typoed_rule_id_warns(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # `CL-001` (missing a digit) is a common, silent typo.
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-001:\n    enabled: false\n")
        load_config(config)
        assert "unknown rule id 'CL-001'" in capsys.readouterr().err

    def test_known_rule_id_does_not_warn(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0001:\n    enabled: false\n")
        load_config(config)
        assert "unknown rule id" not in capsys.readouterr().err

    def test_unknown_top_level_key_warns(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # A top-level `fail_on:` is a natural mistake (it's a CLI flag).
        config = tmp_path / ".compose-lint.yml"
        config.write_text("fail_on: critical\nrules:\n  CL-0001:\n    enabled: false\n")
        load_config(config)
        assert "unknown top-level key 'fail_on'" in capsys.readouterr().err

    def test_unknown_rule_key_warns(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0001:\n    severty: high\n")
        load_config(config)
        assert "unknown key 'severty'" in capsys.readouterr().err

    def test_enabled_quoted_false_raises(self, tmp_path: Path) -> None:
        # A quoted 'false' is a string, not the YAML boolean — it must not be a
        # silent no-op that leaves the rule on (issue #279 G2).
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0001:\n    enabled: 'false'\n")
        with pytest.raises(ConfigError, match="'enabled' must be true or false"):
            load_config(config)

    def test_enabled_zero_raises(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0001:\n    enabled: 0\n")
        with pytest.raises(ConfigError, match="'enabled' must be true or false"):
            load_config(config)

    def test_enabled_yaml_no_still_disables(self, tmp_path: Path) -> None:
        # YAML 1.1 `no` parses to the boolean False, so it legitimately disables.
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0001:\n    enabled: no\n")
        disabled, _overrides, _excluded = load_config(config)
        assert "CL-0001" in disabled

    def test_enabled_true_keeps_rule_active(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0001:\n    enabled: true\n")
        disabled, _overrides, _excluded = load_config(config)
        assert "CL-0001" not in disabled


class TestExcludeServices:
    """Tests for per-service rule exclusions (ADR-010)."""

    def test_list_form(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text(
            "rules:\n"
            "  CL-0003:\n"
            "    exclude_services:\n"
            "      - minecraft\n"
            "      - backup\n"
        )
        _disabled, _overrides, excluded = load_config(config)
        assert excluded == {"CL-0003": {"minecraft": None, "backup": None}}

    def test_mapping_form_with_reasons(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text(
            "rules:\n"
            "  CL-0003:\n"
            "    exclude_services:\n"
            '      minecraft: "entrypoint switches users"\n'
            '      backup: "forks as different user"\n'
        )
        _disabled, _overrides, excluded = load_config(config)
        assert excluded == {
            "CL-0003": {
                "minecraft": "entrypoint switches users",
                "backup": "forks as different user",
            }
        }

    def test_mapping_form_null_reason(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text(
            "rules:\n  CL-0003:\n    exclude_services:\n      minecraft:\n"
        )
        _disabled, _overrides, excluded = load_config(config)
        assert excluded == {"CL-0003": {"minecraft": None}}

    def test_coexists_with_severity_override(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text(
            "rules:\n"
            "  CL-0005:\n"
            "    severity: high\n"
            "    exclude_services:\n"
            "      - internal-admin\n"
        )
        _disabled, overrides, excluded = load_config(config)
        assert overrides["CL-0005"] == Severity.HIGH
        assert excluded["CL-0005"] == {"internal-admin": None}

    def test_absent_when_not_configured(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0003:\n    enabled: false\n")
        _disabled, _overrides, excluded = load_config(config)
        assert excluded == {}

    def test_invalid_scalar_value(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0003:\n    exclude_services: minecraft\n")
        with pytest.raises(ConfigError, match="must be a list or mapping"):
            load_config(config)

    def test_invalid_list_entry(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0003:\n    exclude_services:\n      - 42\n")
        with pytest.raises(ConfigError, match="service name strings"):
            load_config(config)
