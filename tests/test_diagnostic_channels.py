"""The machine-readable diagnostic channels: ``kind``, ``warnings[]``, run-level.

ADR-015's envelope carried ``errors[]`` as ``{file, message}`` only, so a
consumer wanting "fail on a coverage gap but not on a parse error" had to
regex the message, and a gap waived by ``--allow-partial-coverage`` left no
trace in JSON or SARIF at all. These tests pin the shape that replaced that:

- every entry on either channel carries ``kind``, a closed set assigned where
  the condition is detected (``parse``, ``coverage_gap``, ``rule_crash``,
  ``run``), mirrored in SARIF as the notification's ``descriptor.id``;
- ``warnings[]`` is always present and holds waived gaps, which SARIF reports
  as ``level: warning`` without marking the invocation unsuccessful;
- a run-level entry has ``file: ""`` in JSON and no ``locations`` in SARIF;
- a truncated SARIF document says so exactly once.

The CLI runs in-process so the coverage gate sees these paths.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint import cli
from compose_lint.formatters import sarif as sarif_formatter
from compose_lint.models import RuleMetadata, Severity
from compose_lint.rules import BaseRule, _registry

if TYPE_CHECKING:
    from collections.abc import Iterator

    from compose_lint.models import Finding

SARIF_SCHEMA = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"
KINDS = {"parse", "coverage_gap", "rule_crash", "run"}

_CLEAN = "services:\n  web:\n    image: nginx:1.27\n"
_GAP = "include:\n  - nope.yml\nservices:\n  web:\n    image: nginx:1.27\n"


def _run(
    args: list[str],
    cwd: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, Any]:
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("NO_COLOR", "1")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    out = capsys.readouterr().out
    code = exc.value.code if isinstance(exc.value.code, int) else 1
    return code, json.loads(out)


def _notifications(doc: dict[str, Any]) -> list[dict[str, Any]]:
    invocation = doc["runs"][0]["invocations"][0]
    return list(invocation.get("toolExecutionNotifications", []))


def _validate_sarif(doc: dict[str, Any]) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(SARIF_SCHEMA.read_text(encoding="utf-8"))
    validator = jsonschema.validators.validator_for(schema)(schema)
    errors = sorted(validator.iter_errors(doc), key=str)
    assert not errors, "\n".join(e.message for e in errors[:5])


# --- JSON ------------------------------------------------------------------


def test_a_clean_run_has_both_channels_present_and_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "compose.yml").write_text(_CLEAN, encoding="utf-8")
    _, doc = _run(
        ["check", "--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
    )
    assert doc["errors"] == []
    assert doc["warnings"] == []


def test_a_parse_failure_is_kind_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "compose.yml").write_text("services: [unclosed\n", encoding="utf-8")
    code, doc = _run(
        ["check", "--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
    )
    assert code == 2
    assert [e["kind"] for e in doc["errors"]] == ["parse"]
    assert doc["errors"][0]["file"] == "compose.yml"


def test_a_fatal_gap_is_kind_coverage_gap_on_the_error_channel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "compose.yml").write_text(_GAP, encoding="utf-8")
    code, doc = _run(
        ["check", "--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
    )
    assert code == 2
    assert [e["kind"] for e in doc["errors"]] == ["coverage_gap"]
    assert doc["warnings"] == []


def test_a_waived_gap_moves_to_warnings_and_does_not_fail_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Before this, a waived gap left JSON exactly as if there were none."""
    (tmp_path / "compose.yml").write_text(_GAP, encoding="utf-8")
    code, doc = _run(
        [
            "check",
            "--format",
            "json",
            "--allow-partial-coverage",
            "--fail-on",
            "critical",
            "compose.yml",
        ],
        tmp_path,
        monkeypatch,
        capsys,
    )
    assert code == 0
    assert doc["errors"] == []
    assert [w["kind"] for w in doc["warnings"]] == ["coverage_gap"]
    assert doc["warnings"][0]["file"] == "compose.yml"
    assert "nope.yml" in doc["warnings"][0]["message"]


def test_a_run_level_failure_is_kind_run_with_an_empty_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code, doc = _run(["check", "--format", "json"], tmp_path, monkeypatch, capsys)
    assert code == 2
    assert doc["errors"] == [
        {"file": "", "message": doc["errors"][0]["message"], "kind": "run"}
    ]
    assert "no Compose files found" in doc["errors"][0]["message"]


@pytest.fixture
def crashing_rule() -> Iterator[None]:
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

    saved = list(_registry)
    _registry.clear()
    _registry.append(_CrashingRule)
    try:
        yield
    finally:
        _registry.clear()
        _registry.extend(saved)


@pytest.mark.usefixtures("crashing_rule")
def test_a_crashed_rule_is_kind_rule_crash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "compose.yml").write_text(_CLEAN, encoding="utf-8")
    code, doc = _run(
        ["check", "--format", "json", "compose.yml"], tmp_path, monkeypatch, capsys
    )
    assert code == 2
    assert [e["kind"] for e in doc["errors"]] == ["rule_crash"]
    assert "CL-CRASH" in doc["errors"][0]["message"]


# --- SARIF -----------------------------------------------------------------


def test_every_kind_resolves_to_a_driver_notification_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "compose.yml").write_text(_CLEAN, encoding="utf-8")
    _, doc = _run(
        ["check", "--format", "sarif", "compose.yml"], tmp_path, monkeypatch, capsys
    )
    driver = doc["runs"][0]["tool"]["driver"]
    assert {d["id"] for d in driver["notifications"]} == KINDS
    _validate_sarif(doc)


def test_a_waived_gap_is_a_warning_notification_on_a_successful_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "compose.yml").write_text(_GAP, encoding="utf-8")
    _, doc = _run(
        ["check", "--format", "sarif", "--allow-partial-coverage", "compose.yml"],
        tmp_path,
        monkeypatch,
        capsys,
    )
    invocation = doc["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True
    [notification] = _notifications(doc)
    assert notification["level"] == "warning"
    assert notification["descriptor"] == {"id": "coverage_gap"}
    assert notification["locations"], "a gap names the file it was found in"
    _validate_sarif(doc)


def test_a_fatal_gap_is_an_error_notification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "compose.yml").write_text(_GAP, encoding="utf-8")
    code, doc = _run(
        ["check", "--format", "sarif", "compose.yml"], tmp_path, monkeypatch, capsys
    )
    assert code == 2
    assert doc["runs"][0]["invocations"][0]["executionSuccessful"] is False
    [notification] = _notifications(doc)
    assert (notification["level"], notification["descriptor"]["id"]) == (
        "error",
        "coverage_gap",
    )
    _validate_sarif(doc)


def test_a_run_level_notification_has_no_locations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The empty path used to resolve to the working directory's URI."""
    code, doc = _run(["check", "--format", "sarif"], tmp_path, monkeypatch, capsys)
    assert code == 2
    [notification] = _notifications(doc)
    assert notification["descriptor"] == {"id": "run"}
    assert "locations" not in notification
    _validate_sarif(doc)


def test_truncation_is_reported_exactly_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI and the formatter each used to add their own notification."""
    monkeypatch.setattr(sarif_formatter, "MAX_SARIF_RESULTS", 1)
    (tmp_path / "compose.yml").write_text(_CLEAN, encoding="utf-8")
    code, doc = _run(
        ["check", "--format", "sarif", "compose.yml"], tmp_path, monkeypatch, capsys
    )
    assert code == 2
    assert len(doc["runs"][0]["results"]) == 1
    assert doc["runs"][0]["invocations"][0]["executionSuccessful"] is False
    [notification] = _notifications(doc)
    assert notification["descriptor"] == {"id": "run"}
    assert "locations" not in notification
    assert "truncated" in notification["message"]["text"]
    _validate_sarif(doc)


def test_a_strict_config_error_found_after_the_scan_is_kind_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A stale `exclude_services` name under --strict-config is run-level."""
    (tmp_path / "compose.yml").write_text(_CLEAN, encoding="utf-8")
    (tmp_path / ".compose-lint.yml").write_text(
        "rules:\n  CL-0019:\n    exclude_services: [nope]\n", encoding="utf-8"
    )
    code, doc = _run(
        ["check", "--format", "json", "--strict-config", "compose.yml"],
        tmp_path,
        monkeypatch,
        capsys,
    )
    assert code == 2
    assert [(e["file"], e["kind"]) for e in doc["errors"]] == [("", "run")]
    assert "nope" in doc["errors"][0]["message"]
    assert doc["findings"], "the findings are still reported beside the error"
