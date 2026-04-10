"""Tests for the CLI."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "compose_files"


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Run compose-lint CLI as a subprocess."""
    return subprocess.run(
        [sys.executable, "-m", "compose_lint", *args],
        capture_output=True,
        text=True,
    )


class TestCLI:
    """Tests for CLI behavior."""

    def test_version(self) -> None:
        result = run_cli("--version")
        assert result.returncode == 0
        assert "compose-lint" in result.stdout
        assert "0.2.0" in result.stdout

    def test_no_args_no_compose_file(self) -> None:
        result = run_cli()
        assert result.returncode == 2
        assert "no compose files found" in result.stderr.lower()

    def test_file_not_found(self) -> None:
        result = run_cli("nonexistent.yml")
        assert result.returncode == 2
        assert "not found" in result.stderr.lower()

    def test_invalid_compose_file(self) -> None:
        result = run_cli(str(FIXTURES / "invalid_no_services.yml"))
        assert result.returncode == 2
        assert "services" in result.stderr.lower()

    def test_valid_file_no_findings(self) -> None:
        result = run_cli(str(FIXTURES / "valid_basic.yml"))
        assert result.returncode == 0

    def test_json_format_valid_file(self) -> None:
        result = run_cli("--format", "json", str(FIXTURES / "valid_basic.yml"))
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, list)

    def test_invalid_severity(self) -> None:
        result = run_cli("--fail-on", "invalid", str(FIXTURES / "valid_basic.yml"))
        assert result.returncode == 2

    def test_multiple_files(self) -> None:
        result = run_cli(
            str(FIXTURES / "valid_basic.yml"),
            str(FIXTURES / "valid_v2.yml"),
        )
        assert result.returncode == 0
