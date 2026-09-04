"""Tests for config file loading."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from compose_lint.config import (
    _KNOWN_RULE_KEYS,
    KNOWN_TOP_LEVEL_KEYS,
    ConfigError,
    load_config,
)
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

    def test_rules_null_behaves_like_empty_mapping(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n")
        disabled, overrides, excluded = load_config(config)
        assert disabled == {}
        assert overrides == {}
        assert excluded == {}

    def test_per_rule_null_config_behaves_like_empty_mapping(
        self, tmp_path: Path
    ) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0001:\n")
        disabled, overrides, excluded = load_config(config)
        assert "CL-0001" not in disabled
        assert "CL-0001" not in overrides
        assert "CL-0001" not in excluded

    def test_rules_wrong_type_raises(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules: hello\n")
        with pytest.raises(ConfigError, match="'rules' must be a mapping"):
            load_config(config)

    def test_per_rule_wrong_type_raises(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0001: hello\n")
        with pytest.raises(
            ConfigError, match="Config for rule 'CL-0001' must be a mapping"
        ):
            load_config(config)

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


class TestStrictConfig:
    """strict=True escalates config diagnostics to errors (issue #380)."""

    def test_unknown_rule_id_raises(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-001:\n    enabled: false\n")
        with pytest.raises(ConfigError, match="unknown rule id 'CL-001'"):
            load_config(config, strict=True)

    def test_unknown_top_level_key_raises(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("fail_on: high\nrules:\n  CL-0001:\n    enabled: false\n")
        with pytest.raises(ConfigError, match="unknown top-level key 'fail_on'"):
            load_config(config, strict=True)

    def test_unknown_rule_key_raises(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0001:\n    severty: high\n")
        with pytest.raises(ConfigError, match="unknown key 'severty'"):
            load_config(config, strict=True)

    def test_valid_config_still_loads_under_strict(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0001:\n    enabled: false\n")
        disabled, _overrides, _excluded = load_config(config, strict=True)
        assert "CL-0001" in disabled
        assert capsys.readouterr().err == ""

    def test_default_mode_still_warns_not_raises(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Backward compatibility: without strict, an unknown id is a warning.
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-001:\n    enabled: false\n")
        load_config(config)  # no raise
        assert "unknown rule id 'CL-001'" in capsys.readouterr().err


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

    def test_exclude_services_null_behaves_like_empty(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0003:\n    exclude_services:\n")
        _disabled, _overrides, excluded = load_config(config)
        assert excluded == {"CL-0003": {}}

    def test_exclude_services_wrong_type_raises(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0003:\n    exclude_services: 5\n")
        with pytest.raises(ConfigError, match="must be a list or mapping"):
            load_config(config)

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


# --- The config schema is frozen at 1.0, so its key sets are a contract ------
#
# Added after a mutation pass: halving `_KNOWN_RULE_KEYS` to
# `{enabled, reason}` left the entire suite green. `severity:` and
# `exclude_services:` would have started warning as unknown keys — and
# *erroring* under `--strict-config`, which docs/configuration.md recommends
# for CI — with nothing to catch it. `docs/compatibility.md` freezes
# ".compose-lint.yml keys and their semantics" at 1.0, so the sets belong
# under a contract test rather than being implied by the tests that use them.


def test_the_top_level_key_set_is_exact() -> None:
    """Adding a key is a deliberate, documented act (RELEASING.md: MINOR)."""
    assert frozenset({"rules"}) == KNOWN_TOP_LEVEL_KEYS, (
        "the .compose-lint.yml top-level key set changed. That is a config "
        "schema change frozen at 1.0 — document it and update this test."
    )


def test_the_per_rule_key_set_is_exact() -> None:
    assert (
        frozenset({"enabled", "reason", "severity", "exclude_services"})
        == _KNOWN_RULE_KEYS
    ), (
        "the per-rule key set changed. Dropping one makes a valid config warn "
        "as an unknown key, and error under --strict-config."
    )


@pytest.mark.parametrize("key", ["enabled", "reason", "severity", "exclude_services"])
def test_every_documented_per_rule_key_is_accepted(key: str, tmp_path: Path) -> None:
    """Guard the guard: the set above must match what the loader really takes.

    A key could be listed as known and still be rejected downstream, which is
    what the set existing does not by itself prove.
    """
    values = {
        "enabled": "false",
        "reason": "'because'",
        "severity": "low",
        "exclude_services": "{web: 'because'}",
    }
    config = tmp_path / ".compose-lint.yml"
    config.write_text(f"rules:\n  CL-0003:\n    {key}: {values[key]}\n")
    load_config(config)  # must not raise, and must not be an unknown key


# --- The config file is YAML, and `<<:` is YAML ----------------------------


def test_a_merge_key_is_not_a_data_key(tmp_path: Path) -> None:
    """`parser.py` already skips the merge tag for Compose documents.

    The config loader called `construct_object` on every key node, and PyYAML
    has no constructor for the merge tag — so a `<<:` aborted the whole run
    with `could not determine a constructor for the tag
    'tag:yaml.org,2002:merge'`, exit 2, naming no fix. A `<<:` was therefore
    legal in the file being linted and fatal in the config beside it.
    """
    config = tmp_path / ".compose-lint.yml"
    config.write_text(
        "x-off: &off\n"
        "  enabled: false\n"
        "  reason: shared justification\n"
        "rules:\n"
        "  CL-0002:\n"
        "    <<: *off\n",
        encoding="utf-8",
    )
    disabled, _severities, _excluded = load_config(config)
    assert disabled["CL-0002"] == "shared justification"


def test_duplicate_keys_are_still_rejected(tmp_path: Path) -> None:
    """Guard the guard: skipping the merge tag must not skip the dup check."""
    config = tmp_path / ".compose-lint.yml"
    config.write_text(
        "rules:\n  CL-0002:\n    enabled: false\n  CL-0002:\n    enabled: true\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="duplicate key"):
        load_config(config)


def test_an_x_prefixed_top_level_key_is_tolerated(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The other half of `<<:` support: an anchor needs somewhere to live.

    Compose's extension-field convention, already honoured in the documents
    this tool lints. Warning on it — and erroring under `--strict-config` —
    would make the anchor idiom unusable in exactly the pipelines that opted
    into rigor.
    """
    config = tmp_path / ".compose-lint.yml"
    config.write_text("x-shared: {a: b}\nrules: {}\n", encoding="utf-8")
    load_config(config, strict=True)  # must not raise
    assert "unknown top-level key" not in capsys.readouterr().err


def test_a_bare_unknown_top_level_key_still_warns(tmp_path: Path) -> None:
    """`x-` is a deliberate marker, so tolerating it costs no typo detection."""
    config = tmp_path / ".compose-lint.yml"
    config.write_text("rulez: {}\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown top-level key"):
        load_config(config, strict=True)
