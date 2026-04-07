"""Integration tests: full CLI against multi-issue compose files."""

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


class TestIntegration:
    """End-to-end tests against mixed.yml."""

    def test_mixed_file_finds_multiple_issues(self) -> None:
        result = run_cli(str(FIXTURES / "mixed.yml"))
        assert result.returncode == 1
        assert "CL-0001" in result.stdout
        assert "CL-0002" in result.stdout
        assert "CL-0003" in result.stdout
        assert "CL-0004" in result.stdout
        assert "CL-0005" in result.stdout

    def test_mixed_file_json_output(self) -> None:
        result = run_cli(
            "--format", "json", str(FIXTURES / "mixed.yml")
        )
        assert result.returncode == 1
        data = json.loads(result.stdout)
        assert isinstance(data, list)
        assert len(data) > 5

        rule_ids = {f["rule_id"] for f in data}
        assert "CL-0001" in rule_ids
        assert "CL-0002" in rule_ids

        for finding in data:
            assert "file" in finding
            assert "rule_id" in finding
            assert "severity" in finding
            assert "service" in finding
            assert "message" in finding
            assert "fix" in finding
            assert "references" in finding

    def test_mixed_file_fail_on_critical(self) -> None:
        result = run_cli(
            "--fail-on", "critical",
            str(FIXTURES / "mixed.yml"),
        )
        assert result.returncode == 1

    def test_clean_file_exits_zero(self) -> None:
        result = run_cli(str(FIXTURES / "valid_basic.yml"))
        assert result.returncode == 0

    def test_secure_db_not_flagged_for_ports(self) -> None:
        result = run_cli(
            "--format", "json", str(FIXTURES / "mixed.yml")
        )
        data = json.loads(result.stdout)
        db_port_findings = [
            f
            for f in data
            if f["service"] == "db" and f["rule_id"] == "CL-0005"
        ]
        assert len(db_port_findings) == 0

    def test_multiple_files(self) -> None:
        result = run_cli(
            "--format", "json",
            str(FIXTURES / "mixed.yml"),
            str(FIXTURES / "valid_basic.yml"),
        )
        data = json.loads(result.stdout)
        files = {f["file"] for f in data}
        assert len(files) >= 1
