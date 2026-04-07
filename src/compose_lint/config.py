"""Configuration file loading for compose-lint."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from compose_lint.models import Severity


class ConfigError(Exception):
    """Raised when a config file is invalid."""


def _parse_severity(value: str) -> Severity:
    """Parse a severity string from config."""
    try:
        return Severity(value.lower())
    except ValueError:
        choices = ", ".join(s.value for s in Severity)
        raise ConfigError(
            f"Invalid severity '{value}' in config (choose from {choices})"
        ) from None


def load_config(
    path: str | Path | None = None,
) -> tuple[set[str], dict[str, Severity]]:
    """Load a .compose-lint.yml config file.

    Returns a tuple of (disabled_rules, severity_overrides).
    If path is None, looks for .compose-lint.yml in the current directory.
    If no config file is found, returns empty defaults.
    """
    if path is not None:
        config_path = Path(path)
        if not config_path.exists():
            raise ConfigError(f"Config file not found: {path}")
    else:
        config_path = Path(".compose-lint.yml")
        if not config_path.exists():
            return set(), {}

    try:
        content = config_path.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"Cannot read config file: {e}") from e

    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in config file: {e}") from e

    if data is None:
        return set(), {}

    if not isinstance(data, dict):
        raise ConfigError("Config file must be a YAML mapping")

    return _parse_rules(data.get("rules", {}))


def _parse_rules(
    rules: Any,
) -> tuple[set[str], dict[str, Severity]]:
    """Parse the rules section of a config file."""
    if not isinstance(rules, dict):
        raise ConfigError("'rules' must be a mapping")

    disabled: set[str] = set()
    overrides: dict[str, Severity] = {}

    for rule_id, rule_config in rules.items():
        rule_id = str(rule_id)

        if not isinstance(rule_config, dict):
            raise ConfigError(f"Config for rule '{rule_id}' must be a mapping")

        if rule_config.get("enabled") is False:
            disabled.add(rule_id)

        if "severity" in rule_config:
            overrides[rule_id] = _parse_severity(str(rule_config["severity"]))

    return disabled, overrides
