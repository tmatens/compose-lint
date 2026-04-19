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


ExcludedServices = dict[str, dict[str, str | None]]


def load_config(
    path: str | Path | None = None,
) -> tuple[dict[str, str | None], dict[str, Severity], ExcludedServices]:
    """Load a .compose-lint.yml config file.

    Returns a tuple of (disabled_rules, severity_overrides, excluded_services).
    disabled_rules maps rule ID to an optional reason string.
    excluded_services maps rule ID to a mapping of service name to optional
    per-service reason (see ADR-010).
    If path is None, looks for .compose-lint.yml in the current directory.
    If no config file is found, returns empty defaults.
    """
    empty: tuple[dict[str, str | None], dict[str, Severity], ExcludedServices] = (
        {},
        {},
        {},
    )
    if path is not None:
        config_path = Path(path)
        if not config_path.exists():
            raise ConfigError(f"Config file not found: {path}")
    else:
        config_path = Path(".compose-lint.yml")
        if not config_path.exists():
            return empty

    try:
        content = config_path.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"Cannot read config file: {e}") from e

    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in config file: {e}") from e

    if data is None:
        return empty

    if not isinstance(data, dict):
        raise ConfigError("Config file must be a YAML mapping")

    return _parse_rules(data.get("rules", {}))


def _parse_rules(
    rules: Any,
) -> tuple[dict[str, str | None], dict[str, Severity], ExcludedServices]:
    """Parse the rules section of a config file."""
    if not isinstance(rules, dict):
        raise ConfigError("'rules' must be a mapping")

    disabled: dict[str, str | None] = {}
    overrides: dict[str, Severity] = {}
    excluded: ExcludedServices = {}

    for rule_id, rule_config in rules.items():
        rule_id = str(rule_id)

        if not isinstance(rule_config, dict):
            raise ConfigError(f"Config for rule '{rule_id}' must be a mapping")

        if rule_config.get("enabled") is False:
            reason = rule_config.get("reason")
            disabled[rule_id] = str(reason) if reason is not None else None

        if "severity" in rule_config:
            overrides[rule_id] = _parse_severity(str(rule_config["severity"]))

        if "exclude_services" in rule_config:
            excluded[rule_id] = _parse_exclude_services(
                rule_id, rule_config["exclude_services"]
            )

    return disabled, overrides, excluded


def _parse_exclude_services(rule_id: str, value: Any) -> dict[str, str | None]:
    """Parse an exclude_services entry into a service-name → reason mapping.

    Accepts either a list of service names (no reasons) or a mapping of
    service name to reason string.
    """
    if isinstance(value, list):
        result: dict[str, str | None] = {}
        for item in value:
            if not isinstance(item, str):
                raise ConfigError(
                    f"exclude_services for '{rule_id}' list entries must be "
                    "service name strings"
                )
            result[item] = None
        return result

    if isinstance(value, dict):
        result = {}
        for service_name, reason in value.items():
            if not isinstance(service_name, str):
                raise ConfigError(
                    f"exclude_services for '{rule_id}' keys must be "
                    "service name strings"
                )
            if reason is None:
                result[service_name] = None
            else:
                result[service_name] = str(reason)
        return result

    raise ConfigError(f"exclude_services for '{rule_id}' must be a list or mapping")
