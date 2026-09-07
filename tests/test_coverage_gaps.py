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
from compose_lint.parser import load_compose_full

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


def _gap_body(kind: str) -> str:
    """A document whose ``kind`` reference is a coverage gap after ADR-036.

    Neither construct is refused as a class any more: one that resolves inside
    the project is merged, so the shape that is still a gap has to be a
    *residual*. Both legs here point at a file that is not there — pointing
    them at ``base.yml``, which these tests write, would exercise the resolved
    path and assert nothing about gaps at all.
    """
    if kind == "include":
        return "include:\n  - nope.yml\nservices:\n  web:\n    image: nginx:1.27\n"
    return (
        "services:\n  web:\n    image: nginx:1.27\n"
        "    extends:\n      file: nope.yml\n      service: app\n"
    )


# Both messages now say *which* residual the reference hit, rather than the
# flat "is not resolved" every shape shared before ADR-036.
_GAP_PHRASE = {
    "include": "was not found",
    "extends": "was not found",
}


def test_a_gap_names_the_reference_and_the_residual(tmp_path: Path) -> None:
    """ "the file was not found" and "it resolves outside the project directory"
    call for different edits from the reader, so the message says which."""
    target = _write(
        tmp_path / "compose.yml",
        "include:\n  - missing-include.yml\n"
        "services:\n"
        "  web:\n"
        "    image: nginx:1.27\n"
        "    extends:\n"
        "      file: missing-base.yml\n"
        "      service: app\n",
    )
    gaps = load_compose_full(target).gaps

    assert len(gaps) == 2
    included = next(g for g in gaps if "missing-include.yml" in g)
    assert "was not found" in included
    extended = next(g for g in gaps if "missing-base.yml" in g)
    assert "was not found" in extended
    assert "'web'" in extended


def test_a_resolved_reference_is_not_a_gap(tmp_path: Path) -> None:
    """The distinction that matters: nothing is unlinted, so nothing is said."""
    _write(tmp_path / "base.yml", DANGEROUS_BASE)
    target = _write(
        tmp_path / "compose.yml",
        "include:\n  - base.yml\nservices:\n  web:\n    image: nginx:1.27\n",
    )
    assert load_compose_full(target).gaps == ()


def test_in_file_extends_is_not_a_gap(tmp_path: Path) -> None:
    """It is resolved, so nothing is unlinted — the distinction that matters."""
    target = _write(
        tmp_path / "compose.yml",
        "services:\n"
        "  base:\n"
        "    image: nginx:1.27\n"
        "  web:\n"
        "    extends:\n"
        "      service: base\n",
    )
    assert load_compose_full(target).gaps == ()


def test_an_ordinary_file_has_no_gaps(tmp_path: Path) -> None:
    target = _write(
        tmp_path / "compose.yml", "services:\n  web:\n    image: nginx:1.27\n"
    )
    assert load_compose_full(target).gaps == ()


# --- The gate: exit code, not just stderr ---------------------------------


@pytest.mark.parametrize("kind", ["include", "extends"])
def test_a_gap_fails_the_gate_even_when_local_services_are_clean(
    tmp_path: Path, kind: str
) -> None:
    """The false-clean case: nothing locally wrong, everything dangerous hidden."""
    _write(tmp_path / "base.yml", DANGEROUS_BASE)
    hardened = (
        "    read_only: true\n"
        "    cap_drop: [ALL]\n"
        '    security_opt: ["no-new-privileges:true"]\n'
        '    user: "1000:1000"\n'
    )
    if kind == "include":
        body = (
            "include:\n  - nope.yml\n"
            "services:\n"
            "  web:\n"
            "    image: nginx@sha256:" + "ab" * 32 + "\n" + hardened
        )
    else:
        body = (
            "services:\n"
            "  web:\n"
            "    image: nginx@sha256:" + "ab" * 32 + "\n"
            "    extends:\n"
            "      file: nope.yml\n"
            "      service: app\n" + hardened
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
    body = _gap_body(kind)
    target = _write(tmp_path / "compose.yml", body)

    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--format", "json", str(target)])
    assert exc.value.code == 2, kind

    doc = json.loads(capsys.readouterr().out)
    assert doc["errors"], f"{kind}: JSON errors[] is empty"
    assert any(_GAP_PHRASE[kind] in e["message"] for e in doc["errors"]), kind


@pytest.mark.parametrize("kind", ["include", "extends"])
def test_the_gap_is_machine_readable_in_sarif(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    _write(tmp_path / "base.yml", DANGEROUS_BASE)
    body = _gap_body(kind)
    target = _write(tmp_path / "compose.yml", body)

    with pytest.raises(SystemExit):
        cli.main(["check", "--format", "sarif", str(target)])

    invocation = json.loads(capsys.readouterr().out)["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False, kind
    assert any(
        _GAP_PHRASE[kind] in n["message"]["text"]
        for n in invocation["toolExecutionNotifications"]
    ), kind


# --- The opt-out -----------------------------------------------------------


def test_allow_partial_coverage_grades_what_it_can_see(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = _write(
        tmp_path / "compose.yml",
        "include:\n  - nope.yml\n"
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
    target = _write(tmp_path / "compose.yml", _gap_body("include"))

    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--allow-partial-coverage", "--format", "json", str(target)])
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)["errors"] == []


def test_fix_reports_the_gap_without_failing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``fix`` is not the merge gate, so a gap is advisory there."""
    target = _write(
        tmp_path / "compose.yml",
        "include:\n  - nope.yml\nservices:\n  web:\n    image: nginx:1.27\n",
    )

    with pytest.raises(SystemExit) as exc:
        cli.main(["fix", str(target)])
    assert exc.value.code == 0
    assert "include" in capsys.readouterr().err.lower()


# --- The remedy names only what the command can do (#779) -------------------


@pytest.mark.parametrize("kind", ["include", "extends"])
def test_fix_never_names_a_flag_it_does_not_accept(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    """``fix`` inherited ``check``'s remedy verbatim and sent users to
    ``--allow-partial-coverage``, which the ``fix`` subparser rejects. The flag
    is not added to ``fix`` — it never fails on a gap, so there is nothing to
    accept — the sentence is scoped to the caller instead."""
    _write(tmp_path / "base.yml", DANGEROUS_BASE)
    body = _gap_body(kind)
    target = _write(tmp_path / "compose.yml", body)

    with pytest.raises(SystemExit) as exc:
        cli.main(["fix", str(target)])
    assert exc.value.code == 0
    err = capsys.readouterr().err
    assert "--allow-partial-coverage" not in err, kind
    assert "not fixed" in err, kind
    assert "docker compose config" in err, kind

    # The flag really is check-only; the test above is meaningless otherwise.
    with pytest.raises(SystemExit) as exc:
        cli.main(["fix", "--allow-partial-coverage", str(target)])
    assert exc.value.code == 2


@pytest.mark.parametrize("kind", ["include", "extends"])
def test_check_still_names_the_flag_on_every_channel(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    """Scoping the remedy must not cost ``check`` its own: the flag is the
    documented way out, on stderr and in the structured errors alike."""
    _write(tmp_path / "base.yml", DANGEROUS_BASE)
    body = _gap_body(kind)
    target = _write(tmp_path / "compose.yml", body)

    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "--format", "json", str(target)])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "--allow-partial-coverage" in captured.err, kind
    assert "not fixed" not in captured.err, kind
    errors = json.loads(captured.out)["errors"]
    assert any("--allow-partial-coverage" in e["message"] for e in errors), errors


def test_the_parser_states_the_gap_without_prescribing_a_flag(
    tmp_path: Path,
) -> None:
    """The remedy is a CLI concern; the parser has no idea which command asked."""
    target = _write(
        tmp_path / "compose.yml",
        "include:\n  - nope.yml\n"
        "services:\n  web:\n    image: nginx:1.27\n"
        "    extends:\n      file: nope2.yml\n      service: app\n",
    )
    gaps = load_compose_full(target).gaps
    assert len(gaps) == 2
    assert not any("--" in gap for gap in gaps)
