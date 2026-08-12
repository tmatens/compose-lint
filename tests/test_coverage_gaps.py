"""A coverage gap must reach every channel a consumer reads.

compose-lint's shipped deployment model is a merge gate, so "part of this stack
was never linted" has to be as visible as "I found something". Both gaps used to
be invisible to machines: ``include:`` warned on stderr only, and cross-file
``extends: {file: ...}`` said nothing at all. In both cases the verdict, the exit
code, JSON ``errors`` and SARIF ``executionSuccessful`` reported a clean run over
a partial view.

The asymmetry that proved it was a bug: an ``include``-*only* file (no local
services) has always been rejected at parse time with exit 2.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from compose_lint import cli
from compose_lint.parser import coverage_gaps, loads

if TYPE_CHECKING:
    from pathlib import Path

# A base carrying full host control, so a run that misses it is unambiguously
# reporting on something other than what would be deployed.
DANGEROUS_BASE = (
    "services:\n"
    "  app:\n"
    "    image: nginx:1.27\n"
    "    privileged: true\n"
    "    network_mode: host\n"
)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


# --- Detection -------------------------------------------------------------


def test_include_alongside_services_is_a_gap() -> None:
    data, _lines = loads(
        "include:\n  - base.yml\nservices:\n  web:\n    image: nginx:1.27\n"
    )
    assert any("include" in gap for gap in coverage_gaps(data))


def test_cross_file_extends_is_a_gap_and_names_the_service() -> None:
    data, _lines = loads(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.27\n"
        "    extends:\n"
        "      file: base.yml\n"
        "      service: app\n"
    )
    gaps = coverage_gaps(data)
    assert len(gaps) == 1
    assert "extends" in gaps[0]
    assert "'web'" in gaps[0]


def test_in_file_extends_is_not_a_gap() -> None:
    """It is resolved, so nothing is unlinted — the distinction that matters."""
    data, _lines = loads(
        "services:\n"
        "  base:\n"
        "    image: nginx:1.27\n"
        "  web:\n"
        "    extends:\n"
        "      service: base\n"
    )
    assert coverage_gaps(data) == []


def test_an_ordinary_file_has_no_gaps() -> None:
    data, _lines = loads("services:\n  web:\n    image: nginx:1.27\n")
    assert coverage_gaps(data) == []


# --- The gate: exit code, not just stderr ---------------------------------


@pytest.mark.parametrize("kind", ["include", "extends"])
def test_a_gap_fails_the_gate_even_when_local_services_are_clean(
    tmp_path: Path, kind: str
) -> None:
    """The false-clean case: nothing locally wrong, everything dangerous hidden."""
    _write(tmp_path / "base.yml", DANGEROUS_BASE)
    if kind == "include":
        body = (
            "include:\n  - base.yml\n"
            "services:\n"
            "  web:\n"
            "    image: nginx@sha256:" + "ab" * 32 + "\n"
            "    read_only: true\n"
            "    cap_drop: [ALL]\n"
            '    security_opt: ["no-new-privileges:true"]\n'
            '    user: "1000:1000"\n'
        )
    else:
        body = (
            "services:\n"
            "  web:\n"
            "    image: nginx@sha256:" + "ab" * 32 + "\n"
            "    extends:\n"
            "      file: base.yml\n"
            "      service: app\n"
            "    read_only: true\n"
            "    cap_drop: [ALL]\n"
            '    security_opt: ["no-new-privileges:true"]\n'
            '    user: "1000:1000"\n'
        )
    target = _write(tmp_path / "compose.yml", body)

    with pytest.raises(SystemExit) as exc:
        cli.main(["check", str(target)])
    assert exc.value.code == 2, kind


@pytest.mark.parametrize("kind", ["include", "extends"])
def test_the_gap_is_machine_readable_in_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    _write(tmp_path / "base.yml", DANGEROUS_BASE)
    body = (
        "include:\n  - base.yml\nservices:\n  web:\n    image: nginx:1.27\n"
        if kind == "include"
        else (
            "services:\n  web:\n    image: nginx:1.27\n"
            "    extends:\n      file: base.yml\n      service: app\n"
        )
    )
    target = _write(tmp_path / "compose.yml", body)

    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--format", "json", str(target)])
    assert exc.value.code == 2, kind

    doc = json.loads(capsys.readouterr().out)
    assert doc["errors"], f"{kind}: JSON errors[] is empty"
    assert any("not resolved" in e["message"] for e in doc["errors"]), kind


@pytest.mark.parametrize("kind", ["include", "extends"])
def test_the_gap_is_machine_readable_in_sarif(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    _write(tmp_path / "base.yml", DANGEROUS_BASE)
    body = (
        "include:\n  - base.yml\nservices:\n  web:\n    image: nginx:1.27\n"
        if kind == "include"
        else (
            "services:\n  web:\n    image: nginx:1.27\n"
            "    extends:\n      file: base.yml\n      service: app\n"
        )
    )
    target = _write(tmp_path / "compose.yml", body)

    with pytest.raises(SystemExit):
        cli.main(["check", "--format", "sarif", str(target)])

    invocation = json.loads(capsys.readouterr().out)["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False, kind
    assert any(
        "not resolved" in n["message"]["text"]
        for n in invocation["toolExecutionNotifications"]
    ), kind


# --- The opt-out -----------------------------------------------------------


def test_allow_partial_coverage_grades_what_it_can_see(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(tmp_path / "base.yml", DANGEROUS_BASE)
    target = _write(
        tmp_path / "compose.yml",
        "include:\n  - base.yml\n"
        "services:\n  web:\n    image: nginx:1.27\n    privileged: true\n",
    )

    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--allow-partial-coverage", str(target)])
    # The local CRITICAL still fails the gate — the opt-out waives the *gap*,
    # not the findings.
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "CL-0002" in captured.out
    assert "include" in captured.err.lower()


def test_opting_out_keeps_the_gap_out_of_the_structured_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write(tmp_path / "base.yml", DANGEROUS_BASE)
    target = _write(
        tmp_path / "compose.yml",
        "include:\n  - base.yml\nservices:\n  web:\n    image: nginx:1.27\n",
    )

    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--allow-partial-coverage", "--format", "json", str(target)])
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)["errors"] == []


def test_fix_reports_the_gap_without_failing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``fix`` is not the merge gate, so a gap is advisory there."""
    _write(tmp_path / "base.yml", DANGEROUS_BASE)
    target = _write(
        tmp_path / "compose.yml",
        "include:\n  - base.yml\nservices:\n  web:\n    image: nginx:1.27\n",
    )

    with pytest.raises(SystemExit) as exc:
        cli.main(["fix", str(target)])
    assert exc.value.code == 0
    assert "include" in capsys.readouterr().err.lower()
