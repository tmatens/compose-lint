"""Tests for the CLI."""

from __future__ import annotations

import json
import stat
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

    from compose_lint.models import Finding

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

    def test_fail_on_help_lists_severity_choices(self) -> None:
        # --fail-on belongs to the `check` subcommand now (ADR-011); its help
        # surface is `check --help`, not the top-level help.
        result = run_cli("check", "--help")
        assert result.returncode == 0
        # The metavar should advertise the valid values, not a bare FAIL_ON.
        assert "--fail-on {low,medium,high,critical}" in result.stdout
        assert "FAIL_ON" not in result.stdout

    def test_top_level_help_lists_check_subcommand(self) -> None:
        result = run_cli("--help")
        assert result.returncode == 0
        assert "check" in result.stdout

    def test_explicit_check_subcommand_lints(self) -> None:
        result = run_cli("check", str(FIXTURES / "insecure_privileged.yml"))
        assert result.returncode == 1
        assert "CL-0002" in result.stdout

    def test_bare_invocation_still_lints(self) -> None:
        # The argv shim must keep `compose-lint <file>` working as `check`.
        bare = run_cli(str(FIXTURES / "insecure_privileged.yml"))
        explicit = run_cli("check", str(FIXTURES / "insecure_privileged.yml"))
        assert bare.returncode == explicit.returncode == 1
        assert bare.stdout == explicit.stdout

    def test_flag_only_invocation_routes_to_check(self) -> None:
        # `compose-lint -q` (no file, no subcommand) must still reach check and
        # fall through to compose-file discovery, not error at the top level.
        result = run_cli("-q")
        assert result.returncode == 2
        assert "no compose files found" in result.stderr.lower()

    def test_verbose_and_quiet_are_mutually_exclusive(self) -> None:
        result = run_cli("-v", "-q", str(FIXTURES / "insecure_socket.yml"))
        assert result.returncode == 2
        assert "not allowed with" in result.stderr.lower()

    def test_quiet_omits_fix_blocks(self) -> None:
        result = run_cli("-q", str(FIXTURES / "insecure_socket.yml"))
        assert "CL-0001" in result.stdout
        assert "fix:" not in result.stdout
        assert "ref:" not in result.stdout

    def test_header_precedes_error_in_combined_output(self, tmp_path: Path) -> None:
        # With stdout+stderr merged (as CI captures them), the buffered header
        # must not land after the unbuffered error line.
        bad = tmp_path / "bad.yml"
        bad.write_text("services: [\n")
        result = subprocess.run(
            [sys.executable, "-m", "compose_lint", str(bad)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        combined = result.stdout
        assert "compose-lint" in combined and "Error:" in combined
        assert combined.index("compose-lint") < combined.index("Error:")

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
        assert data["version"] == "1"
        assert data["tool"]["name"] == "compose-lint"
        assert isinstance(data["findings"], list)

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
        by_service = {
            f["service"]: f for f in data["findings"] if f["rule_id"] == "CL-0003"
        }
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

    def test_explain_rejects_structured_format(self) -> None:
        for fmt in ("json", "sarif"):
            result = run_cli("--explain", "CL-0003", "--format", fmt)
            assert result.returncode == 2, fmt
            assert "no JSON or SARIF form" in result.stderr
            assert result.stdout == ""

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

    def test_json_envelope_clean_run(self) -> None:
        result = run_cli(
            "--fail-on",
            "low",
            "--format",
            "json",
            str(FIXTURES / "safe_self_hosted.yml"),
        )
        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert data["version"] == "1"
        assert data["tool"]["name"] == "compose-lint"
        assert data["tool"]["version"]
        assert data["findings"] == []
        assert data["errors"] == []

    def test_json_errors_lists_parse_failures(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("services: [\n")
        result = run_cli(
            "--format",
            "json",
            str(FIXTURES / "valid_basic.yml"),
            str(bad),
        )
        assert result.returncode == 2
        data = json.loads(result.stdout)
        assert len(data["errors"]) == 1
        assert data["errors"][0]["file"] == str(bad)
        assert data["errors"][0]["message"]

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
        # `bad` lives outside the repo working directory, so it is emitted as an
        # absolute, percent-encoded file: URI rather than the raw OS path (S1).
        assert uri == bad.resolve().as_uri()

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


_BARE_SERVICE = "services:\n  web:\n    image: nginx:1.27\n"


class TestFixSubcommand:
    """Tests for the hidden, experimental `fix` subcommand (ADR-014).

    Post-Phase-2 `fix` is reachable without ``COMPOSE_LINT_EXPERIMENTAL``, so
    these invoke it with a plain ``run_cli``; the env var now only gates SARIF
    fixes (see ``test_sarif``).
    """

    def test_dry_run_prints_diff_to_stdout(self, tmp_path: Path) -> None:
        f = tmp_path / "docker-compose.yml"
        f.write_text(_BARE_SERVICE)
        result = run_cli("fix", str(f))
        assert result.returncode == 0
        # Diff (data) on stdout; warning + status (human) on stderr.
        assert "+    read_only: true" in result.stdout
        assert "⚠ behavior-changing · CL-0007" in result.stdout
        assert "experimental" in result.stderr.lower()
        # Dry-run writes nothing.
        assert f.read_text() == _BARE_SERVICE

    def test_apply_writes_file_and_emits_no_diff(self, tmp_path: Path) -> None:
        f = tmp_path / "docker-compose.yml"
        f.write_text(_BARE_SERVICE)
        result = run_cli("fix", "--apply", str(f))
        assert result.returncode == 0
        assert result.stdout == ""
        patched = f.read_text()
        assert "read_only: true" in patched
        assert "no-new-privileges:true" in patched

    def test_apply_preserves_file_mode(self, tmp_path: Path) -> None:
        # --apply swaps the file in atomically; the new file must keep the
        # original's permission bits, not inherit the temp file's 0600.
        f = tmp_path / "docker-compose.yml"
        f.write_text(_BARE_SERVICE)
        f.chmod(0o640)
        result = run_cli("fix", "--apply", str(f))
        assert result.returncode == 0
        assert stat.S_IMODE(f.stat().st_mode) == 0o640
        assert "read_only: true" in f.read_text()

    def test_only_restricts_to_named_rule(self, tmp_path: Path) -> None:
        f = tmp_path / "docker-compose.yml"
        f.write_text(_BARE_SERVICE)
        run_cli("fix", "--apply", "--only", "CL-0007", str(f))
        patched = f.read_text()
        assert "read_only: true" in patched
        assert "no-new-privileges" not in patched

    def test_respects_config_suppression(self, tmp_path: Path) -> None:
        f = tmp_path / "docker-compose.yml"
        f.write_text(_BARE_SERVICE)
        config = tmp_path / ".compose-lint.yml"
        config.write_text("rules:\n  CL-0007:\n    enabled: false\n")
        run_cli("fix", "--apply", "--config", str(config), str(f))
        patched = f.read_text()
        # CL-0007 suppressed => not fixed; CL-0003 still applied.
        assert "read_only: true" not in patched
        assert "no-new-privileges:true" in patched

    def test_hidden_from_help(self) -> None:
        # Always registered post-Phase-2, but still omitted from --help.
        result = run_cli("--help")
        assert result.returncode == 0
        assert "fix" not in result.stdout

    def test_available_without_env_gate(self, tmp_path: Path) -> None:
        f = tmp_path / "docker-compose.yml"
        f.write_text(_BARE_SERVICE)
        # Phase 2: `fix` runs without COMPOSE_LINT_EXPERIMENTAL — still hidden,
        # still warned-on, dry-run by default (writes nothing).
        result = run_cli("fix", str(f))
        assert result.returncode == 0
        assert "experimental" in result.stderr.lower()
        assert "+    read_only: true" in result.stdout
        assert f.read_text() == _BARE_SERVICE

    def test_apply_refuses_to_write_invalid_compose(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # Safety net (ADR-014, issue #261): if the engine ever computes invalid
        # Compose, --apply must refuse and leave the file untouched. Force a
        # broken result to exercise the guard end-to-end (in-process so the
        # patched engine is reachable).
        from compose_lint import cli

        f = tmp_path / "docker-compose.yml"
        f.write_text(_BARE_SERVICE)
        monkeypatch.setattr(cli, "apply_edits", lambda text, edits: "services: [\n")
        with pytest.raises(SystemExit) as exc:
            cli.main(["fix", "--apply", str(f)])
        assert exc.value.code == 2
        assert "does not parse as Compose" in capsys.readouterr().err
        assert f.read_text() == _BARE_SERVICE  # nothing written

    def test_apply_refuses_to_write_structural_drift(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # Beyond the parse net (ADR-014): a patch that is valid Compose but
        # mutates a service no fixer touched must also be refused, untouched.
        # Force such a patch (valid YAML, an extra service) to drive the guard.
        from compose_lint import cli

        f = tmp_path / "docker-compose.yml"
        f.write_text(_BARE_SERVICE)
        drifted = _BARE_SERVICE + "  ghost:\n    image: scratch\n"
        monkeypatch.setattr(cli, "apply_edits", lambda text, edits: drifted)
        with pytest.raises(SystemExit) as exc:
            cli.main(["fix", "--apply", str(f)])
        assert exc.value.code == 2
        assert "added or removed a service" in capsys.readouterr().err
        assert f.read_text() == _BARE_SERVICE  # nothing written


class TestRuleCrashExitCode:
    """A rule that raises maps to exit 2, not a clean/findings exit (#279 E1)."""

    def test_rule_crash_exits_2_with_diagnostic(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from compose_lint import cli
        from compose_lint.models import RuleMetadata, Severity
        from compose_lint.rules import BaseRule, _registry

        class _CrashingRule(BaseRule):
            @property
            def metadata(self) -> RuleMetadata:
                return RuleMetadata(
                    id="CL-CRASH",
                    name="Crashing rule",
                    description="Always raises",
                    severity=Severity.HIGH,
                )

            def check(self, *_: object) -> Iterator[Finding]:
                raise RuntimeError("boom")
                yield  # pragma: no cover - makes this a generator

        f = tmp_path / "docker-compose.yml"
        f.write_text(_BARE_SERVICE)

        saved = list(_registry)
        _registry.clear()
        _registry.append(_CrashingRule)
        try:
            with pytest.raises(SystemExit) as exc:
                cli.main(["check", str(f)])
        finally:
            _registry.clear()
            _registry.extend(saved)

        # Exit 2: "compose-lint itself couldn't run" (ADR-006), distinguishable
        # from a clean run (0) and from real findings (1).
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "CL-CRASH" in err
        assert "RuntimeError" in err
