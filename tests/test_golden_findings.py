"""The golden finding set, and the surfaces that must match it (#621).

Every cross-surface smoke asserted one bit — exit 0 versus exit 1.
``tests/smoke/insecure.yml`` trips six rules and only CL-0002 is at or
above the default threshold, so a surface could stop reporting the other
five and every smoke in the repo stayed green. Fewer findings, same
verdict: invisible in exactly the direction that matters for a security
linter.

``tests/smoke/insecure.golden.json`` is the shared answer, and
``scripts/assert_golden_findings.py`` is the comparator the workflows call
for the Docker and pre-commit surfaces. These tests cover the CLI surface
and, more importantly, keep the golden honest — a golden nobody
regenerates becomes a golden everybody forces past.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from tests._cli_env import cli_env

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPARATOR = REPO_ROOT / "scripts" / "assert_golden_findings.py"
GOLDEN = REPO_ROOT / "tests" / "smoke" / "insecure.golden.json"
FIXTURE = "tests/smoke/insecure.yml"


def _lint(*args: str) -> str:
    proc = subprocess.run(
        [sys.executable, "-m", "compose_lint", "check", *args, FIXTURE],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=cli_env(PYTHONPATH=str(REPO_ROOT / "src"), NO_COLOR="1"),
        timeout=120,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return proc.stdout


def _compare(
    report: str, *extra: str, tmp_path: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Hand the comparator a file, the way the workflows do.

    Not stdin: a text report carries the verdict marks and excerpt gutters
    (⚠ · │ ─), and piping those to a subprocess on Windows deadlocked the
    parent — the test timed out at 60s rather than failing (#621). Writing
    UTF-8 to a file and passing the path is both what CI actually does and
    the one shape that behaves the same on every platform.
    """
    target = (tmp_path or Path(tempfile.mkdtemp())) / "report.txt"
    target.write_text(report, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(COMPARATOR), "--surface", "test", *extra, str(target)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )


def test_the_golden_still_describes_the_fixture() -> None:
    """The golden must never be allowed to drift from the working tree.

    If this fails, a rule started or stopped firing on the shared fixture.
    That is a real change and may well be correct — regenerate with the
    command in the golden's own ``_comment`` and read the diff. What must
    not happen is the surfaces being held to an answer the tool no longer
    gives.
    """
    result = _compare(_lint("--format", "json", "--fail-on", "low"))
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_golden_is_not_empty() -> None:
    """Guard the guard: an empty golden would match a broken surface."""
    findings = json.loads(GOLDEN.read_text(encoding="utf-8"))["findings"]
    assert len(findings) >= 5
    assert {f["severity"] for f in findings} >= {"critical", "medium", "low"}
    assert not any(f["suppressed"] for f in findings), (
        "the golden is generated without a config; a suppressed entry means it "
        "was captured from a configured run and the surfaces would inherit that"
    )


@pytest.mark.parametrize("fail_on", ["low", "medium", "high", "critical"])
def test_the_golden_holds_at_every_threshold(fail_on: str) -> None:
    """--fail-on moves the exit code, not the result set.

    This is the property that lets one golden serve every surface: each
    smoke picks the threshold that keeps its own step green, and the
    comparison is unaffected.
    """
    result = _compare(_lint("--format", "json", "--fail-on", fail_on))
    assert result.returncode == 0, result.stdout + result.stderr


def test_sarif_matches_the_same_golden() -> None:
    """The Action writes SARIF and never JSON, so the comparator reads both."""
    result = _compare(_lint("--format", "sarif", "--fail-on", "critical"))
    assert result.returncode == 0, result.stdout + result.stderr


def test_a_dropped_finding_is_caught() -> None:
    """The whole point: a surface reporting less must fail, not pass quietly."""
    report = json.loads(_lint("--format", "json", "--fail-on", "low"))
    report["findings"] = [f for f in report["findings"] if f["rule_id"] != "CL-0006"]
    result = _compare(json.dumps(report))
    assert result.returncode == 1
    assert "CL-0006" in result.stdout
    assert "missing" in result.stdout


def test_an_unexpected_finding_is_caught() -> None:
    """Extra is as wrong as missing — this is set equality, not a subset."""
    report = json.loads(_lint("--format", "json", "--fail-on", "low"))
    invented = dict(report["findings"][0])
    invented["rule_id"] = "CL-9999"
    report["findings"].append(invented)
    result = _compare(json.dumps(report))
    assert result.returncode == 1
    assert "unexpected" in result.stdout


def test_a_silently_applied_config_is_caught() -> None:
    """A surface that picked up a config the others did not is a divergence.

    It is also how the Docker mount question (#625) would surface here: a
    quietly smaller effective result set rather than an error.
    """
    report = json.loads(_lint("--format", "json", "--fail-on", "low"))
    report["findings"][0]["suppressed"] = True
    result = _compare(json.dumps(report))
    assert result.returncode == 1
    assert "suppressed" in result.stdout


def test_a_regraded_severity_is_caught() -> None:
    report = json.loads(_lint("--format", "json", "--fail-on", "low"))
    report["findings"][0]["severity"] = "low"
    result = _compare(json.dumps(report))
    assert result.returncode == 1
    assert "severity" in result.stdout


def test_text_mode_catches_a_missing_rule() -> None:
    """The pre-commit surface's only available view."""
    text = _lint("--fail-on", "low")
    assert _compare(text, "--in-text").returncode == 0
    thinned = "\n".join(line for line in text.splitlines() if "CL-0019" not in line)
    result = _compare(thinned, "--in-text")
    assert result.returncode == 1
    assert "CL-0019" in result.stdout


def test_more_than_one_linted_file_is_refused() -> None:
    """(rule, line) is only unambiguous for a single file.

    Both shared fixtures carry CL-0003 at line 6, so a multi-file report
    would collide silently. The comparator refuses rather than compare.
    """
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "compose_lint",
            "check",
            "--format",
            "json",
            "--fail-on",
            "low",
            FIXTURE,
            "tests/smoke/sarif-shape.yml",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=cli_env(PYTHONPATH=str(REPO_ROOT / "src"), NO_COLOR="1"),
        timeout=120,
    )
    result = _compare(proc.stdout)
    assert result.returncode == 1
    assert "exactly one linted file" in result.stdout
