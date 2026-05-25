"""Tests for SARIF 2.1.0 formatter."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from compose_lint.formatters.sarif import (
    build_sarif_log,
    format_findings,
)
from compose_lint.models import Finding, Severity, TextEdit

FIXTURES = Path(__file__).parent / "compose_files"
SARIF_SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"


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

    def test_fix_surfaced_in_properties(self) -> None:
        results = format_findings([_sample_finding()], "docker-compose.yml")
        assert "fixes" not in results[0]
        assert results[0]["properties"]["fix"] == "Use a Docker socket proxy."

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
        assert "properties" not in results[0]

    def test_region_omitted_when_line_unknown(self) -> None:
        # A missing line cannot be a valid region (startLine must be >= 1), so the
        # location carries only artifactLocation rather than a fabricated line 1.
        finding = Finding(
            rule_id="CL-0001",
            severity=Severity.CRITICAL,
            service="web",
            message="test",
            line=None,
        )
        results = format_findings([finding], "test.yml")
        loc = results[0]["locations"][0]["physicalLocation"]
        assert "region" not in loc
        assert loc["artifactLocation"]["uri"] == "test.yml"

    def test_registered_rule_has_matching_index(self) -> None:
        results = format_findings([_sample_finding()], "test.yml")
        log = build_sarif_log(results)
        rules = log["runs"][0]["tool"]["driver"]["rules"]
        idx = results[0]["ruleIndex"]
        assert rules[idx]["id"] == results[0]["ruleId"]

    def test_unregistered_rule_omits_index(self) -> None:
        # An index would have to point somewhere; defaulting to 0 falsely
        # attributes the result to the first registered rule. Omit it instead.
        finding = Finding(
            rule_id="CL-9999",
            severity=Severity.HIGH,
            service="web",
            message="phantom rule",
            line=3,
        )
        results = format_findings([finding], "test.yml")
        assert results[0]["ruleId"] == "CL-9999"
        assert "ruleIndex" not in results[0]

    def test_empty_findings(self) -> None:
        results = format_findings([], "docker-compose.yml")
        assert results == []

    def test_severity_mapping(self) -> None:
        for severity, expected_level in [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
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


class TestStructuredFixes:
    """Tests for SARIF ``fixes[].artifactChanges`` from the fix engine."""

    def test_insertion_maps_to_replacement(self) -> None:
        f = _sample_finding()
        edit = TextEdit(3, 1, 3, 1, "    read_only: true\n")
        results = format_findings([f], "docker-compose.yml", fixes=[(f, [edit])])
        fixes = results[0]["fixes"]
        assert len(fixes) == 1
        change = fixes[0]["artifactChanges"][0]
        assert change["artifactLocation"]["uri"] == "docker-compose.yml"
        rep = change["replacements"][0]
        assert rep["deletedRegion"] == {
            "startLine": 3,
            "startColumn": 1,
            "endLine": 3,
            "endColumn": 1,
        }
        assert rep["insertedContent"]["text"] == "    read_only: true\n"

    def test_pure_deletion_omits_inserted_content(self) -> None:
        f = _sample_finding()
        edit = TextEdit(5, 1, 6, 1, "")
        results = format_findings([f], "x.yml", fixes=[(f, [edit])])
        rep = results[0]["fixes"][0]["artifactChanges"][0]["replacements"][0]
        assert rep["deletedRegion"]["startLine"] == 5
        assert "insertedContent" not in rep

    def test_multiple_edits_become_multiple_replacements(self) -> None:
        f = _sample_finding()
        edits = [TextEdit(3, 1, 3, 1, "a\n"), TextEdit(7, 1, 8, 1, "")]
        results = format_findings([f], "x.yml", fixes=[(f, edits)])
        replacements = results[0]["fixes"][0]["artifactChanges"][0]["replacements"]
        assert len(replacements) == 2

    def test_caveat_becomes_fix_description(self) -> None:
        f = _sample_finding()
        edit = TextEdit(3, 1, 3, 1, "x\n", caveat="changes runtime behavior")
        results = format_findings([f], "x.yml", fixes=[(f, [edit])])
        assert results[0]["fixes"][0]["description"]["text"] == (
            "changes runtime behavior"
        )

    def test_no_caveat_omits_description(self) -> None:
        f = _sample_finding()
        edit = TextEdit(3, 1, 3, 1, "x\n")
        results = format_findings([f], "x.yml", fixes=[(f, [edit])])
        assert "description" not in results[0]["fixes"][0]

    def test_finding_without_edits_has_no_fixes(self) -> None:
        with_fix = _sample_finding()
        without_fix = Finding(
            rule_id="CL-0002",
            severity=Severity.HIGH,
            service="db",
            message="privileged",
            line=9,
            fix="Drop privileged.",
        )
        edit = TextEdit(3, 1, 3, 1, "x\n")
        results = format_findings(
            [with_fix, without_fix],
            "x.yml",
            fixes=[(with_fix, [edit])],
        )
        assert "fixes" in results[0]
        assert "fixes" not in results[1]
        # the un-fixed finding keeps its prose guidance
        assert results[1]["properties"]["fix"] == "Drop privileged."

    def test_fixes_absent_when_argument_omitted(self) -> None:
        results = format_findings([_sample_finding()], "x.yml")
        assert "fixes" not in results[0]


class TestBuildSarifLog:
    """Tests for complete SARIF log structure."""

    def test_schema_and_version(self) -> None:
        log = build_sarif_log([])
        assert log["version"] == "2.1.0"
        # The canonical, immutable OASIS errata01 URL — not a mutable branch ref.
        assert log["$schema"] == (
            "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
            "sarif-schema-2.1.0.json"
        )

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

    def _run_sarif(self, *, experimental: bool) -> dict:
        env = dict(os.environ)
        if experimental:
            env["COMPOSE_LINT_EXPERIMENTAL"] = "1"
        else:
            env.pop("COMPOSE_LINT_EXPERIMENTAL", None)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "compose_lint",
                "--format",
                "sarif",
                str(FIXTURES / "insecure_no_new_priv.yml"),
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        return json.loads(result.stdout)

    def test_structured_fixes_emitted_under_experimental(self) -> None:
        data = self._run_sarif(experimental=True)
        results = data["runs"][0]["results"]
        with_fixes = [r for r in results if "fixes" in r]
        assert with_fixes, "expected structured fixes when experimental is enabled"
        change = with_fixes[0]["fixes"][0]["artifactChanges"][0]
        assert change["replacements"]

    def test_structured_fixes_gated_off_by_default(self) -> None:
        data = self._run_sarif(experimental=False)
        results = data["runs"][0]["results"]
        assert all("fixes" not in r for r in results)
        # the prose guidance is still present
        assert any("properties" in r for r in results)


class TestSarifSchemaCompliance:
    """Validate emitted SARIF against the canonical OASIS 2.1.0 schema."""

    def _validate(self, log: dict[str, object], tmp_path: Path) -> None:
        if shutil.which("check-jsonschema") is None:
            pytest.skip("check-jsonschema not installed")
        out = tmp_path / "out.sarif.json"
        out.write_text(json.dumps(log))
        result = subprocess.run(
            [
                "check-jsonschema",
                "--schemafile",
                str(SARIF_SCHEMA_PATH),
                str(out),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"SARIF schema validation failed:\n{result.stdout}\n{result.stderr}"
        )

    def test_log_with_fix_validates(self, tmp_path: Path) -> None:
        results = format_findings([_sample_finding()], "test.yml")
        log = build_sarif_log(results)
        self._validate(log, tmp_path)

    def test_log_without_fix_validates(self, tmp_path: Path) -> None:
        finding = Finding(
            rule_id="CL-0001",
            severity=Severity.HIGH,
            service="web",
            message="no-fix finding",
            line=2,
        )
        log = build_sarif_log(format_findings([finding], "test.yml"))
        self._validate(log, tmp_path)

    def test_log_with_parse_errors_validates(self, tmp_path: Path) -> None:
        log = build_sarif_log(
            format_findings([_sample_finding()], "test.yml"),
            parse_errors=[("broken.yml", "could not parse")],
        )
        self._validate(log, tmp_path)

    def test_log_with_structured_fix_validates(self, tmp_path: Path) -> None:
        f = _sample_finding()
        edits = [
            TextEdit(3, 1, 3, 1, "    read_only: true\n", caveat="behavior change"),
            TextEdit(5, 1, 6, 1, ""),
        ]
        log = build_sarif_log(
            format_findings([f], "test.yml", fixes=[(f, edits)]),
        )
        self._validate(log, tmp_path)


class TestPartialFingerprints:
    """Each result carries a stable fingerprint for GitHub dedup/tracking (S3)."""

    def test_present_on_every_result(self) -> None:
        results = format_findings([_sample_finding()], "x.yml")
        fp = results[0]["partialFingerprints"]
        assert isinstance(fp["composeLintFinding/v1"], str)
        assert len(fp["composeLintFinding/v1"]) == 64  # sha256 hex

    def test_stable_across_runs(self) -> None:
        a = format_findings([_sample_finding()], "x.yml")[0]
        b = format_findings([_sample_finding()], "x.yml")[0]
        assert a["partialFingerprints"] == b["partialFingerprints"]

    def test_independent_of_line_number(self) -> None:
        # An alert should survive an unrelated line shift, so the fingerprint
        # must not change when only the line moves.
        base = _sample_finding()
        moved = Finding(
            rule_id=base.rule_id,
            severity=base.severity,
            service=base.service,
            message=base.message,
            line=base.line + 100,
        )
        fa = format_findings([base], "x.yml")[0]["partialFingerprints"]
        fb = format_findings([moved], "x.yml")[0]["partialFingerprints"]
        assert fa == fb

    def test_differs_by_rule_service_and_message(self) -> None:
        base = _sample_finding()
        variants = [
            Finding("CL-0002", base.severity, base.service, base.message, base.line),
            Finding(base.rule_id, base.severity, "other", base.message, base.line),
            Finding(base.rule_id, base.severity, base.service, "other msg", base.line),
        ]
        baseline = format_findings([base], "x.yml")[0]["partialFingerprints"]
        for v in variants:
            other = format_findings([v], "x.yml")[0]["partialFingerprints"]
            assert other != baseline


class TestArtifactUri:
    """`artifactLocation.uri` is a conformant, GitHub-resolvable URI (S1)."""

    def test_in_tree_path_is_relative_with_base_id(self, tmp_path: Path) -> None:
        # A file under the working directory becomes a repo-relative path tagged
        # with the SRCROOT base id rather than a non-resolvable absolute path.
        sub = tmp_path / "stack"
        sub.mkdir()
        target = sub / "docker-compose.yml"
        target.touch()
        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            loc = format_findings([_sample_finding()], str(target))[0]
            art = loc["locations"][0]["physicalLocation"]["artifactLocation"]
        finally:
            os.chdir(cwd)
        assert art["uri"] == "stack/docker-compose.yml"
        assert art["uriBaseId"] == "SRCROOT"

    def test_relative_input_stays_relative(self) -> None:
        loc = format_findings([_sample_finding()], "docker-compose.yml")[0]
        art = loc["locations"][0]["physicalLocation"]["artifactLocation"]
        assert art["uri"] == "docker-compose.yml"
        assert art["uriBaseId"] == "SRCROOT"

    def test_spaces_and_unicode_are_percent_encoded(self, tmp_path: Path) -> None:
        d = tmp_path / "my dir"
        d.mkdir()
        target = d / "café.yml"
        target.touch()
        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            art = format_findings([_sample_finding()], str(target))[0]["locations"][0][
                "physicalLocation"
            ]["artifactLocation"]
        finally:
            os.chdir(cwd)
        assert art["uri"] == "my%20dir/caf%C3%A9.yml"
        assert " " not in art["uri"]

    def test_out_of_tree_path_is_absolute_file_uri(self, tmp_path: Path) -> None:
        # A path that does not live under the working directory cannot be made
        # repo-relative without a `..`, so it falls back to an absolute file: URI
        # (percent-encoded, no base id).
        outside = tmp_path / "outside space.yml"
        outside.touch()
        work = tmp_path / "work"
        work.mkdir()
        cwd = os.getcwd()
        os.chdir(work)
        try:
            art = format_findings([_sample_finding()], str(outside))[0]["locations"][0][
                "physicalLocation"
            ]["artifactLocation"]
        finally:
            os.chdir(cwd)
        assert art["uri"].startswith("file://")
        assert "outside%20space.yml" in art["uri"]
        assert "uriBaseId" not in art

    def test_log_declares_src_root_and_working_directory(self) -> None:
        run = build_sarif_log(format_findings([_sample_finding()], "x.yml"))["runs"][0]
        base = run["originalUriBaseIds"]["SRCROOT"]["uri"]
        assert base.startswith("file://")
        assert base.endswith("/")
        assert run["invocations"][0]["workingDirectory"]["uri"] == base

    def test_fix_and_notification_uris_are_normalized(self, tmp_path: Path) -> None:
        f = _sample_finding()
        edit = TextEdit(3, 1, 3, 1, "x\n")
        sub = tmp_path / "stack"
        sub.mkdir()
        target = sub / "compose.yml"
        target.touch()
        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            results = format_findings([f], str(target), fixes=[(f, [edit])])
            fix_uri = results[0]["fixes"][0]["artifactChanges"][0]["artifactLocation"]
            log = build_sarif_log(results, parse_errors=[(str(target), "broken")])
        finally:
            os.chdir(cwd)
        assert fix_uri == {"uri": "stack/compose.yml", "uriBaseId": "SRCROOT"}
        notif = log["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]
        notif_art = notif["locations"][0]["physicalLocation"]["artifactLocation"]
        assert notif_art == {"uri": "stack/compose.yml", "uriBaseId": "SRCROOT"}
