"""Configuration file loading for compose-lint."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

from compose_lint.models import Severity

# Top-level keys the config schema defines today (docs/configuration.md).
# Anything else is almost certainly a typo or a misplaced CLI flag (e.g. a
# top-level `fail_on:`), so we warn rather than silently drop it (issue #279 G1).
_KNOWN_TOP_LEVEL_KEYS = frozenset({"rules", "profiles"})

# Recognized keys inside the `profiles` block (ADR-017).
_KNOWN_PROFILES_KEYS = frozenset({"enabled", "path"})

# Recognized keys inside a per-rule block. A key outside this set (a typo'd
# `severty:` or a `reason:` with no `enabled: false`) is silently inert today;
# warn so the user learns their override never took effect (issue #279 G1).
_KNOWN_RULE_KEYS = frozenset({"enabled", "reason", "severity", "exclude_services"})


class ConfigError(Exception):
    """Raised when a config file is invalid."""


def _warn(message: str, strict: bool = False) -> None:
    """Emit a config diagnostic — a stderr warning, or a hard error under strict.

    Mirrors the CLI's unknown-service warning (ADR-010): a misconfiguration that
    silently weakens a security control should be visible, but config and
    Compose files evolve independently, so by default it must not hard-fail the
    run. Under strict-config (``--strict-config``, #380) the same diagnostics are
    raised as ``ConfigError`` instead, so a typo'd rule id or key fails loudly
    rather than silently no-op'ing where stderr may be suppressed.
    """
    if strict:
        raise ConfigError(message)
    print(f"Warning: {message}", file=sys.stderr)


def _known_rule_ids() -> set[str]:
    """Return the set of registered rule IDs for config validation."""
    from compose_lint.rules import get_registered_rules

    return {cls().metadata.id for cls in get_registered_rules()}


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
    strict: bool = False,
) -> tuple[dict[str, str | None], dict[str, Severity], ExcludedServices]:
    """Load a .compose-lint.yml config file.

    Returns a tuple of (disabled_rules, severity_overrides, excluded_services).
    disabled_rules maps rule ID to an optional reason string.
    excluded_services maps rule ID to a mapping of service name to optional
    per-service reason (see ADR-010).
    If path is None, looks for .compose-lint.yml in the current directory.
    If no config file is found, returns empty defaults.
    When strict is True, config diagnostics that are normally warnings (unknown
    top-level key, unknown/typo'd rule id, unknown rule key) are raised as
    ConfigError instead (#380).
    """
    data = _read_raw_config(path)
    if data is None:
        return {}, {}, {}

    for key in data:
        if str(key) not in _KNOWN_TOP_LEVEL_KEYS:
            _warn(
                f"config: unknown top-level key '{key}' (recognized: "
                f"{', '.join(sorted(_KNOWN_TOP_LEVEL_KEYS))}); it has no effect",
                strict,
            )

    return _parse_rules(data.get("rules", {}), strict)


def _read_raw_config(path: str | Path | None) -> dict[str, Any] | None:
    """Read and parse a config file to a mapping, or None when there is none.

    Returns None when no config file is found (implicit path) or the file is
    empty. Raises ConfigError for an explicitly-named missing file, a read
    error, invalid YAML, or a non-mapping top level.
    """
    if path is not None:
        config_path = Path(path)
        if not config_path.exists():
            raise ConfigError(f"Config file not found: {path}")
    else:
        config_path = Path(".compose-lint.yml")
        if not config_path.exists():
            return None

    try:
        content = config_path.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"Cannot read config file: {e}") from e

    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in config file: {e}") from e

    if data is None:
        return None

    if not isinstance(data, dict):
        raise ConfigError("Config file must be a YAML mapping")

    return data


def load_profiles_config(
    path: str | Path | None = None,
    strict: bool = False,
) -> tuple[bool, str | None]:
    """Return ``(enabled, catalog_path)`` for profile enrichment (ADR-017 §7).

    Off by default, and with **no built-in catalog**: enrichment is a no-op
    unless the user both enables it and points ``profiles.path`` at a catalog
    they trust. Reads the same file as ``load_config``; the top-level
    key-validation warning is emitted there, so this only validates the
    ``profiles`` block itself.
    """
    data = _read_raw_config(path)
    if data is None:
        return False, None

    profiles = data.get("profiles", {})
    if not isinstance(profiles, dict):
        raise ConfigError("'profiles' must be a mapping")

    for key in profiles:
        if str(key) not in _KNOWN_PROFILES_KEYS:
            _warn(
                f"config: profiles has unknown key '{key}' (recognized: "
                f"{', '.join(sorted(_KNOWN_PROFILES_KEYS))}); it has no effect",
                strict,
            )

    enabled = profiles.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigError(
            f"Config: profiles.enabled must be true or false, not {enabled!r}"
        )

    catalog_path = profiles.get("path")
    if catalog_path is not None and not isinstance(catalog_path, str):
        raise ConfigError(
            f"Config: profiles.path must be a string, not {catalog_path!r}"
        )
    return enabled, catalog_path


def _parse_rules(
    rules: Any,
    strict: bool = False,
) -> tuple[dict[str, str | None], dict[str, Severity], ExcludedServices]:
    """Parse the rules section of a config file."""
    if not isinstance(rules, dict):
        raise ConfigError("'rules' must be a mapping")

    disabled: dict[str, str | None] = {}
    overrides: dict[str, Severity] = {}
    excluded: ExcludedServices = {}
    known_ids = _known_rule_ids()

    for rule_id, rule_config in rules.items():
        rule_id = str(rule_id)

        if not isinstance(rule_config, dict):
            raise ConfigError(f"Config for rule '{rule_id}' must be a mapping")

        if rule_id not in known_ids:
            _warn(
                f"config: unknown rule id '{rule_id}'; the override has no effect "
                "(check for a typo or a retired rule)",
                strict,
            )

        for key in rule_config:
            if str(key) not in _KNOWN_RULE_KEYS:
                _warn(
                    f"config: rule '{rule_id}' has unknown key '{key}' (recognized: "
                    f"{', '.join(sorted(_KNOWN_RULE_KEYS))}); it has no effect",
                    strict,
                )

        if "enabled" in rule_config:
            enabled = rule_config["enabled"]
            if not isinstance(enabled, bool):
                raise ConfigError(
                    f"Config for rule '{rule_id}': 'enabled' must be true or false, "
                    f"not {enabled!r} — a quoted 'false', 0, or no would otherwise "
                    "silently leave the rule on"
                )
            if enabled is False:
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
