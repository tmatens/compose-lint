"""Tests for SARIF 2.1.0 formatter."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from compose_lint.formatters.sarif import (
    build_sarif_log,
    format_findings,
)
from compose_lint.models import Finding, Severity

FIXTURES = Path(__file__).parent / "compose_files"


def _sample_finding() -> Finding:
    return Finding(
        rule_id="CL-0001",
        severity=Severity.CRITICAL,
        service="web",
        message="Docker socket mounted via '/var/run/docker.sock'.",
        line=5,
        fix="Use a Docker socket proxy.",
        references=["https://example.com/owasp"],
    )


class TestFormatFindings:
    """Tests for SARIF result formatting."""

    def test_basic_result_structure(self) -> None:
        results = format_findings([_sample_finding()], "docker-compose.yml")
        assert len(results) == 1
        r = results[0]
        assert r["ruleId"] == "CL-0001"
        assert r["level"] == "error"
        assert r["message"]["text"] == _sample_finding().message

    def test_location_includes_file_and_line(self) -> None:
        results = format_findings([_sample_finding()], "docker-compose.yml")
        loc = results[0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "docker-compose.yml"
        assert loc["region"]["startLine"] == 5

    def test_fix_included_when_present(self) -> None:
        results = format_findings([_sample_finding()], "docker-compose.yml")
        assert "fixes" in results[0]
        assert results[0]["fixes"][0]["description"]["text"] == (
            "Use a Docker socket proxy."
        )

    def test_no_fix_when_absent(self) -> None:
        finding = Finding(
            rule_id="CL-0001",
            severity=Severity.CRITICAL,
            service="web",
            message="test",
            line=1,
        )
        results = format_findings([finding], "test.yml")
        assert "fixes" not in results[0]

    def test_line_defaults_to_1_when_none(self) -> None:
        finding = Finding(
            rule_id="CL-0001",
            severity=Severity.CRITICAL,
            service="web",
            message="test",
            line=None,
        )
        results = format_findings([finding], "test.yml")
        loc = results[0]["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] == 1

    def test_empty_findings(self) -> None:
        results = format_findings([], "docker-compose.yml")
        assert results == []

    def test_severity_mapping(self) -> None:
        for severity, expected_level in [
            (Severity.CRITICAL, "error"),
            (Severity.ERROR, "error"),
            (Severity.WARNING, "warning"),
        ]:
            finding = Finding(
                rule_id="CL-0001",
                severity=severity,
                service="web",
                message="test",
                line=1,
            )
            results = format_findings([finding], "test.yml")
            assert results[0]["level"] == expected_level


class TestBuildSarifLog:
    """Tests for complete SARIF log structure."""

    def test_schema_and_version(self) -> None:
        log = build_sarif_log([])
        assert log["version"] == "2.1.0"
        assert "$schema" in log
        assert "sarif-schema-2.1.0" in log["$schema"]

    def test_has_single_run(self) -> None:
        log = build_sarif_log([])
        assert len(log["runs"]) == 1

    def test_tool_driver_info(self) -> None:
        log = build_sarif_log([])
        driver = log["runs"][0]["tool"]["driver"]
        assert driver["name"] == "compose-lint"
        assert "version" in driver
        assert "informationUri" in driver

    def test_rules_populated_from_registry(self) -> None:
        log = build_sarif_log([])
        rules = log["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert "CL-0001" in rule_ids
        assert "CL-0005" in rule_ids
        assert "CL-0010" in rule_ids

    def test_rules_have_security_severity(self) -> None:
        log = build_sarif_log([])
        for rule in log["runs"][0]["tool"]["driver"]["rules"]:
            severity = rule["properties"]["security-severity"]
            assert isinstance(severity, str)
            assert float(severity) > 0

    def test_results_included(self) -> None:
        results = format_findings([_sample_finding()], "test.yml")
        log = build_sarif_log(results)
        assert len(log["runs"][0]["results"]) == 1

    def test_valid_json_roundtrip(self) -> None:
        results = format_findings([_sample_finding()], "test.yml")
        log = build_sarif_log(results)
        dumped = json.dumps(log, indent=2)
        parsed = json.loads(dumped)
        assert parsed["version"] == "2.1.0"


class TestSarifCLI:
    """CLI integration tests for SARIF output."""

    def test_sarif_output_valid_json(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "compose_lint",
                "--format",
                "sarif",
                str(FIXTURES / "insecure_socket.yml"),
            ],
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) > 0

    def test_sarif_clean_file(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "compose_lint",
                "--format",
                "sarif",
                str(FIXTURES / "valid_basic.yml"),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["runs"][0]["results"] == []

    def test_sarif_multiple_files(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "compose_lint",
                "--format",
                "sarif",
                str(FIXTURES / "insecure_socket.yml"),
                str(FIXTURES / "insecure_privileged.yml"),
            ],
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout)
        results = data["runs"][0]["results"]
        files = {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in results
        }
        assert len(files) >= 2
