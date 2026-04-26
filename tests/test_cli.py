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
        from compose_lint import __version__

        assert __version__ in result.stdout

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

    def test_fragment_file_skipped_with_exit_zero(self) -> None:
        # ADR-013: fragments are skipped (exit 0) with a per-file stderr note,
        # so a directory sweep doesn't fail because someone has a `-f` overlay.
        result = run_cli(str(FIXTURES / "fragment_volumes_only.yml"))
        assert result.returncode == 0
        assert "fragment" in result.stderr.lower()

    def test_legacy_v1_file_skipped_with_exit_zero(self) -> None:
        # ADR-013: v1 files are skipped (exit 0). Stderr message must mention
        # the 2023 retirement so users know the format isn't broken — Docker
        # just stopped supporting it.
        result = run_cli(str(FIXTURES / "legacy_v1_compose.yml"))
        assert result.returncode == 0
        assert "compose v1" in result.stderr.lower()
        assert "2023" in result.stderr

    def test_skipped_file_does_not_block_subsequent_lint(self) -> None:
        # The point of exit-0 skip: in `compose-lint a.yml b.yml c.yml`, a
        # fragment in the middle must not hide findings from the file after it.
        result = run_cli(
            str(FIXTURES / "valid_basic.yml"),
            str(FIXTURES / "fragment_volumes_only.yml"),
            str(FIXTURES / "insecure_privileged.yml"),
        )
        # insecure_privileged.yml has CL-0002 at HIGH (default fail-on),
        # so the run must reach it and exit 1.
        assert result.returncode == 1
        assert "CL-0002" in result.stdout
        assert "fragment" in result.stderr.lower()

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

    def test_exclude_services_suppresses_named_service(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text(
            "rules:\n"
            "  CL-0003:\n"
            "    exclude_services:\n"
            '      missing: "entrypoint switches users"\n'
        )
        result = run_cli(
            "--config",
            str(config),
            "--format",
            "json",
            str(FIXTURES / "insecure_no_new_priv.yml"),
        )
        assert result.returncode in (0, 1)
        data = json.loads(result.stdout)
        by_service = {f["service"]: f for f in data if f["rule_id"] == "CL-0003"}
        assert by_service["missing"]["suppressed"] is True
        assert (
            by_service["missing"]["suppression_reason"] == "entrypoint switches users"
        )
        assert by_service["empty_security_opt"]["suppressed"] is False

    def test_explain_prints_rule_doc(self) -> None:
        result = run_cli("--explain", "CL-0003")
        assert result.returncode == 0
        assert "CL-0003: Privilege Escalation Not Blocked" in result.stdout
        assert "no-new-privileges:true" in result.stdout

    def test_explain_is_case_insensitive(self) -> None:
        result = run_cli("--explain", "cl-0003")
        assert result.returncode == 0
        assert "CL-0003" in result.stdout

    def test_explain_unknown_rule_exits_2(self) -> None:
        result = run_cli("--explain", "CL-9999")
        assert result.returncode == 2
        assert "unknown rule id" in result.stderr.lower()
        assert "CL-9999" in result.stderr

    def test_explain_rejects_malformed_id(self) -> None:
        result = run_cli("--explain", "not-a-rule")
        assert result.returncode == 2
        assert result.stderr

    def test_explain_rejects_file_argument(self) -> None:
        result = run_cli("--explain", "CL-0003", str(FIXTURES / "valid_basic.yml"))
        assert result.returncode == 2
        assert "--explain" in result.stderr
        assert "FILE" in result.stderr

    def test_text_default_dedupes_fix_blocks_per_rule(self) -> None:
        # Issue #156: in default text mode the fix block should print only on
        # the first occurrence of each rule id within a file. Subsequent
        # occurrences carry "(see fix above)" instead of repeating the block.
        result = run_cli(str(FIXTURES / "mixed.yml"))
        assert result.returncode == 1
        # mixed.yml fires CL-0003 on multiple services; the prose fix line
        # should appear exactly once.
        assert result.stdout.count("- no-new-privileges:true") == 1
        assert "(see fix above)" in result.stdout

    def test_text_verbose_repeats_fix_blocks(self) -> None:
        # Issue #156: -v / --verbose restores per-finding fix repetition for
        # IDE tooling and local fix-it-now workflows.
        default_result = run_cli(str(FIXTURES / "mixed.yml"))
        verbose_result = run_cli("-v", str(FIXTURES / "mixed.yml"))
        assert verbose_result.returncode == default_result.returncode
        assert verbose_result.stdout.count("- no-new-privileges:true") > 1
        assert "(see fix above)" not in verbose_result.stdout

    def test_text_groups_findings_by_service(self) -> None:
        # Issue #156: text output is grouped under per-service blocks rather
        # than as a flat list. Each service in mixed.yml should have a
        # `service: <name>` header preceding its findings.
        result = run_cli(str(FIXTURES / "mixed.yml"))
        for service in ("traefik", "web", "db"):
            assert f"service: {service}" in result.stdout

    def test_parse_error_does_not_block_subsequent_files(self, tmp_path: Path) -> None:
        # Issue #158: a malformed file in argv must not silently mask
        # findings on the parseable files that come after it.
        bad = tmp_path / "bad.yml"
        bad.write_text("services: [\n")
        result = run_cli(
            str(FIXTURES / "valid_basic.yml"),
            str(bad),
            str(FIXTURES / "insecure_privileged.yml"),
        )
        # CL-0002 (HIGH) from insecure_privileged must reach output.
        assert "CL-0002" in result.stdout
        # Parse error wins exit code.
        assert result.returncode == 2
        assert str(bad) in result.stderr

    def test_parse_error_messages_include_filepath(self, tmp_path: Path) -> None:
        bad = tmp_path / "broken.yml"
        bad.write_text("services: [\n")
        result = run_cli(str(bad))
        assert result.returncode == 2
        assert str(bad) in result.stderr

    def test_missing_file_does_not_block_subsequent_files(self, tmp_path: Path) -> None:
        result = run_cli(
            "definitely-not-a-file.yml",
            str(FIXTURES / "insecure_privileged.yml"),
        )
        assert result.returncode == 2
        assert "definitely-not-a-file.yml" in result.stderr
        assert "CL-0002" in result.stdout

    def test_text_footer_reports_skipped_count(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("services: [\n")
        result = run_cli(
            str(FIXTURES / "valid_basic.yml"),
            str(bad),
        )
        assert result.returncode == 2
        assert "skipped" in result.stdout.lower()
        assert "failed to parse" in result.stdout.lower()

    def test_sarif_includes_parse_error_notifications(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("services: [\n")
        result = run_cli(
            "--format",
            "sarif",
            str(FIXTURES / "valid_basic.yml"),
            str(bad),
        )
        assert result.returncode == 2
        log = json.loads(result.stdout)
        invocation = log["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is False
        notifications = invocation["toolExecutionNotifications"]
        assert len(notifications) == 1
        uri = notifications[0]["locations"][0]["physicalLocation"]["artifactLocation"][
            "uri"
        ]
        assert uri == str(bad)

    def test_sarif_clean_run_marks_execution_successful(self) -> None:
        result = run_cli(
            "--format",
            "sarif",
            str(FIXTURES / "valid_basic.yml"),
        )
        assert result.returncode == 0
        log = json.loads(result.stdout)
        assert log["runs"][0]["invocations"][0]["executionSuccessful"] is True

    def test_exclude_services_unknown_service_warns(self, tmp_path: Path) -> None:
        config = tmp_path / ".compose-lint.yml"
        config.write_text(
            "rules:\n  CL-0003:\n    exclude_services:\n      - does-not-exist\n"
        )
        result = run_cli(
            "--config",
            str(config),
            "--format",
            "json",
            str(FIXTURES / "insecure_no_new_priv.yml"),
        )
        assert "unknown service 'does-not-exist'" in result.stderr
        assert "CL-0003" in result.stderr
