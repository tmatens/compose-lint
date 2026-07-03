"""Tests for the profiles config block (ADR-017)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from compose_lint.config import ConfigError, load_config, load_profiles_config

if TYPE_CHECKING:
    from pathlib import Path


def _write(tmp_path: Path, body: str) -> str:
    cfg = tmp_path / ".compose-lint.yml"
    cfg.write_text(body, encoding="utf-8")
    return str(cfg)


def test_disabled_and_pathless_by_default(tmp_path: Path) -> None:
    assert load_profiles_config(_write(tmp_path, "rules: {}\n")) == (False, None)


def test_enabled_true(tmp_path: Path) -> None:
    cfg = _write(tmp_path, "profiles:\n  enabled: true\n")
    assert load_profiles_config(cfg) == (True, None)


def test_enabled_false(tmp_path: Path) -> None:
    cfg = _write(tmp_path, "profiles:\n  enabled: false\n")
    assert load_profiles_config(cfg) == (False, None)


def test_path_is_returned(tmp_path: Path) -> None:
    cfg = _write(tmp_path, "profiles:\n  enabled: true\n  path: ./my-catalog\n")
    assert load_profiles_config(cfg) == (True, "./my-catalog")


def test_missing_explicit_file_raises() -> None:
    with pytest.raises(ConfigError):
        load_profiles_config("/nonexistent/.compose-lint.yml")


def test_non_bool_enabled_raises(tmp_path: Path) -> None:
    cfg = _write(tmp_path, "profiles:\n  enabled: 'yes'\n")
    with pytest.raises(ConfigError):
        load_profiles_config(cfg)


def test_non_string_path_raises(tmp_path: Path) -> None:
    cfg = _write(tmp_path, "profiles:\n  enabled: true\n  path: 123\n")
    with pytest.raises(ConfigError):
        load_profiles_config(cfg)


def test_profiles_not_a_mapping_raises(tmp_path: Path) -> None:
    cfg = _write(tmp_path, "profiles: true\n")
    with pytest.raises(ConfigError):
        load_profiles_config(cfg)


def test_unknown_profiles_key_warns(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = _write(tmp_path, "profiles:\n  enabled: true\n  bogus: 1\n")
    load_profiles_config(cfg)
    assert "unknown key 'bogus'" in capsys.readouterr().err


def test_profiles_key_not_flagged_as_unknown_top_level(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = _write(tmp_path, "profiles:\n  enabled: true\n")
    load_config(cfg)
    assert "unknown top-level key" not in capsys.readouterr().err
