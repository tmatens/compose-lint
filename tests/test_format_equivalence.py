"""text, json and sarif must describe the same run (#623).

Each formatter had its own tests, asserting its own expectations. Nothing
asserted the three agree, so a formatter could drop a finding, re-grade a
severity, or lose a suppression and only its own test would notice — and
that test would be asserting the new behaviour.

Format selection is a user-experience choice, not a semantic one: json is
for a machine, sarif is for Code Scanning, text is for a human at a
terminal. All three are views of one result set, and the failure this
guards is the quiet one — a human's terminal and their Code Scanning
dashboard disagreeing about what is wrong with their stack.

The fixture is deliberately wide: several rules, three severities, more
than one file, and a suppression carrying a reason.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from tests._cli_env import cli_env

REPO_ROOT = Path(__file__).resolve().parent.parent

# The documented correspondence (formatters/sarif.py `_SARIF_LEVEL`). Stated
# here independently so a change to the mapping has to be made twice, on
# purpose, rather than propagating silently into "the formats still agree".
SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}

SUPPRESSED_RULE = "CL-0003"
SUPPRESSION_REASON = "accepted risk, tracked in TICKET-42"
CONFIG = (
    f"rules:\n  {SUPPRESSED_RULE}:\n    enabled: false\n"
    f'    reason: "{SUPPRESSION_REASON}"\n'
)
TARGETS = ["tests/smoke/insecure.yml", "tests/smoke/sarif-shape.yml"]


class Finding(NamedTuple):
    """The identity all three views can express.

    File and line are in every format; the service name is not (see
    ``test_sarif_still_cannot_name_the_service``). Two files in one run can
    carry the same rule at the same line — the shared fixtures do exactly
    that — so the file is part of the key, not decoration.
    """

    file: str
    rule_id: str
    line: int


class Detail(NamedTuple):
    severity: str  # "" when suppressed: the views spell that differently
    suppressed: bool
    service: str | None  # None where the format cannot say


def _run(*args: str, cwd: Path) -> str:
    proc = subprocess.run(
        [sys.executable, "-m", "compose_lint", "check", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=cli_env(PYTHONPATH=str(REPO_ROOT / "src"), NO_COLOR="1"),
        timeout=120,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return proc.stdout


@pytest.fixture(scope="module")
def workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A checkout-relative run, so paths in every format are comparable."""
    ws = tmp_path_factory.mktemp("fmt")
    (ws / "tests" / "smoke").mkdir(parents=True)
    for target in TARGETS:
        (ws / target).write_bytes((REPO_ROOT / target).read_bytes())
    (ws / "policy.yml").write_text(CONFIG, encoding="utf-8")
    return ws


@pytest.fixture(scope="module")
def outputs(workspace: Path) -> dict[str, str]:
    common = ["--fail-on", "low", "--config", "policy.yml", *TARGETS]
    return {
        "text": _run(*common, cwd=workspace),
        "quiet": _run("--quiet", *common, cwd=workspace),
        "json": _run("--format", "json", *common, cwd=workspace),
        "sarif": _run("--format", "sarif", *common, cwd=workspace),
    }


# --- parsing each view into the same shape -------------------------------

_FILE_HEADER = re.compile(r"^(\S+\.ya?ml)$")
_SERVICE_HEADER = re.compile(r"^\s+service: (\S+)\s+\(line \d+\)")
_ROW = re.compile(r"^\s*(\d+)\s+(SUPPRESSED|CRITICAL|HIGH|MEDIUM|LOW)\s+(CL-\d{4})\b")


def _from_text(out: str) -> dict[Finding, Detail]:
    """Read the rendered table back, tracking which file and service we are in."""
    parsed: dict[Finding, Detail] = {}
    current_file = ""
    current_service: str | None = None
    for raw in out.splitlines():
        header = _FILE_HEADER.match(raw)
        if header:
            current_file, current_service = header.group(1), None
            continue
        service = _SERVICE_HEADER.match(raw)
        if service:
            current_service = service.group(1)
            continue
        row = _ROW.match(raw)
        if row:
            line, severity, rule = row.groups()
            suppressed = severity == "SUPPRESSED"
            parsed[Finding(current_file, rule, int(line))] = Detail(
                "" if suppressed else severity.lower(), suppressed, current_service
            )
    return parsed


def _from_json(out: str) -> dict[Finding, Detail]:
    payload: dict[str, Any] = json.loads(out)
    return {
        Finding(f["file"], f["rule_id"], f["line"]): Detail(
            "" if f["suppressed"] else f["severity"],
            bool(f["suppressed"]),
            f["service"],
        )
        for f in payload["findings"]
    }


def _from_sarif(out: str) -> dict[Finding, Detail]:
    parsed: dict[Finding, Detail] = {}
    for r in json.loads(out)["runs"][0]["results"]:
        location = r["locations"][0]
        physical = location["physicalLocation"]
        suppressed = bool(r.get("suppressions"))
        logical = location.get("logicalLocations") or [{}]
        finding = Finding(
            physical["artifactLocation"]["uri"],
            r["ruleId"],
            physical["region"]["startLine"],
        )
        parsed[finding] = Detail(
            "" if suppressed else r["level"], suppressed, logical[0].get("name")
        )
    return parsed


# --- the comparisons ------------------------------------------------------


def test_the_fixture_is_wide_enough_to_be_worth_comparing(
    outputs: dict[str, str],
) -> None:
    """Guard the guard: a thin document makes every assertion below vacuous."""
    findings = _from_json(outputs["json"])
    assert len(findings) >= 5
    severities = {d.severity for d in findings.values() if not d.suppressed}
    assert len(severities) >= 3, f"only {severities} exercised"
    assert any(d.suppressed for d in findings.values()), "no suppression exercised"


def test_all_three_report_the_same_findings(outputs: dict[str, str]) -> None:
    """Set equality, not counts — a substituted rule id keeps the count."""
    text = set(_from_text(outputs["quiet"]))
    js = set(_from_json(outputs["json"]))
    sarif = set(_from_sarif(outputs["sarif"]))
    assert text == js, f"text vs json: only-text={text - js} only-json={js - text}"
    assert js == sarif, f"json vs sarif: only-json={js - sarif} only-sarif={sarif - js}"


def test_severity_agrees_through_the_documented_mapping(
    outputs: dict[str, str],
) -> None:
    js = _from_json(outputs["json"])
    text = _from_text(outputs["quiet"])
    sarif = _from_sarif(outputs["sarif"])
    for finding, (severity, suppressed, _svc) in js.items():
        if suppressed:
            continue
        assert text[finding].severity == severity, f"{finding}: text disagrees"
        assert sarif[finding].severity == SEVERITY_TO_SARIF_LEVEL[severity], (
            f"{finding}: sarif level {sarif[finding].severity!r} is not the documented "
            f"rendering of {severity!r}"
        )


def test_suppression_state_agrees(outputs: dict[str, str]) -> None:
    js = _from_json(outputs["json"])
    text = _from_text(outputs["quiet"])
    sarif = _from_sarif(outputs["sarif"])
    for finding, (_severity, suppressed, _svc) in js.items():
        assert text[finding].suppressed == suppressed, (
            f"{finding}: text suppression differs"
        )
        assert sarif[finding].suppressed == suppressed, (
            f"{finding}: sarif suppression differs"
        )
    assert any(d.suppressed for d in js.values())


def test_text_and_json_agree_on_the_service(outputs: dict[str, str]) -> None:
    """The two views that can name a service must name the same one.

    This is what a user acts on — "which of my services is wrong" — and it
    is reconstructed differently in each view: json carries it per finding,
    the terminal groups findings under a ``service:`` heading. A grouping
    bug puts a finding under the wrong heading while the json stays right.
    """
    text = _from_text(outputs["quiet"])
    js = _from_json(outputs["json"])
    for finding, detail in js.items():
        assert text[finding].service == detail.service, (
            f"{finding}: text groups it under {text[finding].service!r}, "
            f"json says {detail.service!r}"
        )


def test_the_suppression_reason_survives_into_every_view(
    outputs: dict[str, str],
) -> None:
    """One value wearing three names (AGENTS.md).

    A suppression whose reason is lost is a suppression nobody can audit.
    """
    entry = next(
        f
        for f in json.loads(outputs["json"])["findings"]
        if f["rule_id"] == SUPPRESSED_RULE
    )
    assert entry["suppression_reason"] == SUPPRESSION_REASON

    result = next(
        r
        for r in json.loads(outputs["sarif"])["runs"][0]["results"]
        if r["ruleId"] == SUPPRESSED_RULE and r.get("suppressions")
    )
    assert result["suppressions"][0]["justification"] == SUPPRESSION_REASON

    # Text carries it on a continuation line under the row; `--quiet` is
    # documented as one line per finding, so it is not expected there.
    assert SUPPRESSION_REASON in outputs["text"]
    assert SUPPRESSION_REASON not in outputs["quiet"]


def test_all_three_name_the_same_service(outputs: dict[str, str]) -> None:
    """SARIF can name the service now, so all three views are compared on it.

    This test replaces ``test_sarif_still_cannot_name_the_service``, which
    pinned the gap: SARIF results carried only ``ruleId``,
    ``artifactLocation`` and ``startLine``, so a Code Scanning user had the
    line number where a terminal user had the name. The service now rides as
    a ``logicalLocation``, and the equivalence key widens accordingly — which
    is exactly what that test's docstring said would happen.
    """
    text = _from_text(outputs["quiet"])
    js = _from_json(outputs["json"])
    sarif = _from_sarif(outputs["sarif"])
    for finding, detail in js.items():
        assert detail.service, f"{finding}: json lost the service name"
        assert text[finding].service == detail.service, f"{finding}: text differs"
        assert sarif[finding].service == detail.service, (
            f"{finding}: sarif logicalLocation says "
            f"{sarif[finding].service!r}, json says {detail.service!r}"
        )


def test_the_sarif_title_names_the_service(outputs: dict[str, str]) -> None:
    """``logicalLocations`` is structured; the title is what a user reads.

    GitHub renders ``message.text`` as the alert title and gives no
    guarantee it surfaces a logical location anywhere a reader will look, so
    the name goes in both. Losing it from the title would be invisible to
    the structural comparison above.
    """
    for result in json.loads(outputs["sarif"])["runs"][0]["results"]:
        service = (result["locations"][0].get("logicalLocations") or [{}])[0].get(
            "name"
        )
        if not service:
            continue
        assert f"'{service}'" in result["message"]["text"], (
            f"{result['ruleId']}: title does not name the service — "
            f"{result['message']['text'][:80]!r}"
        )
