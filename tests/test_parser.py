"""Tests for the Compose file parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from compose_lint.parser import ComposeError, load_compose

FIXTURES = Path(__file__).parent / "compose_files"


class TestLoadCompose:
    """Tests for load_compose function."""

    def test_basic_valid_file(self) -> None:
        data, lines = load_compose(FIXTURES / "valid_basic.yml")
        assert "services" in data
        assert "web" in data["services"]
        assert "db" in data["services"]
        assert data["services"]["web"]["image"] == "nginx:1.27-alpine"

    def test_returns_plain_dicts(self) -> None:
        data, _lines = load_compose(FIXTURES / "valid_basic.yml")
        assert isinstance(data, dict)
        assert isinstance(data["services"], dict)
        assert isinstance(data["services"]["web"], dict)

    def test_no_lines_metadata_in_data(self) -> None:
        data, _lines = load_compose(FIXTURES / "valid_basic.yml")
        assert "__lines__" not in data
        assert "__lines__" not in data["services"]
        assert "__lines__" not in data["services"]["web"]

    def test_line_numbers_present(self) -> None:
        _data, lines = load_compose(FIXTURES / "valid_basic.yml")
        assert "services" in lines
        assert "services.web" in lines
        assert "services.db" in lines
        assert lines["services"] == 1
        assert lines["services.web"] > 0
        assert lines["services.db"] > lines["services.web"]

    def test_anchors_and_merge_keys(self) -> None:
        data, _lines = load_compose(FIXTURES / "valid_anchors.yml")
        web = data["services"]["web"]
        assert web["restart"] == "unless-stopped"
        assert web["image"] == "nginx:1.27-alpine"

    def test_v2_with_version_key(self) -> None:
        data, _lines = load_compose(FIXTURES / "valid_v2.yml")
        assert "services" in data
        assert "web" in data["services"]

    def test_env_interpolation_preserved(self) -> None:
        data, _lines = load_compose(FIXTURES / "valid_env_interpolation.yml")
        app = data["services"]["app"]
        assert "${APP_VERSION:-latest}" in app["image"]

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_compose(FIXTURES / "nonexistent.yml")

    def test_empty_file(self) -> None:
        with pytest.raises(ComposeError, match="file is empty"):
            load_compose(FIXTURES / "invalid_empty.yml")

    def test_no_services_key(self) -> None:
        with pytest.raises(ComposeError, match="missing 'services' key"):
            load_compose(FIXTURES / "invalid_no_services.yml")

    def test_services_not_mapping(self) -> None:
        with pytest.raises(ComposeError, match="'services' must be a mapping"):
            load_compose(FIXTURES / "invalid_services_not_mapping.yml")

    def test_service_not_mapping(self) -> None:
        with pytest.raises(ComposeError, match="service 'web' must be a mapping"):
            load_compose(FIXTURES / "invalid_service_not_mapping.yml")

    def test_invalid_yaml(self) -> None:
        with pytest.raises(ComposeError, match="Invalid YAML"):
            load_compose(FIXTURES / "invalid_yaml.yml")
