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
            disabled, overrides = load_config()
            assert disabled == {}
            assert overrides == {}
        finally:
            os.chdir(old_cwd)

    def test_disable_rule(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0001:\n    enabled: false\n")
        disabled, overrides = load_config(config)
        assert "CL-0001" in disabled

    def test_severity_override(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0005:\n    severity: high\n")
        disabled, overrides = load_config(config)
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
        disabled, overrides = load_config(config)
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
        disabled, overrides = load_config(config)
        assert "CL-0001" in disabled
        assert disabled["CL-0001"] == "SEC-1234 approved by J. Smith"

    def test_disable_rule_without_reason(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0001:\n    enabled: false\n")
        disabled, overrides = load_config(config)
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
        disabled, overrides = load_config(config)
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
