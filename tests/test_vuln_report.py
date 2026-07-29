"""Tests for the rolling fixable-vulnerability report (scripts/vuln_report.py).

Runs the actual script as a subprocess — the same entry point CI invokes —
over synthetic pip-audit and Docker Scout payloads.

The behaviour that matters most here is the *negative* case: a missing or
malformed scanner report must fail loudly rather than render an empty
"nothing to fix" body, which would read as an all-clear.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "vuln_report.py"

PIP_AUDIT_MIXED = {
    "dependencies": [
        {
            "name": "tuf",
            "version": "6.0.0",
            "vulns": [{"id": "GHSA-qp9x-wp8f-qgjj", "fix_versions": ["7.0.0"]}],
        },
        {
            "name": "pyjwt",
            "version": "2.10.1",
            "vulns": [{"id": "PYSEC-2025-183", "fix_versions": []}],
        },
        {"name": "compose-lint", "skip_reason": "editable", "vulns": []},
    ]
}

SCOUT_SARIF = {
    "runs": [
        {
            "tool": {
                "driver": {
                    "rules": [
                        {
                            "id": "CVE-2026-0001",
                            "shortDescription": {"text": "zlib overflow"},
                            "properties": {"security-severity": "5.5"},
                        },
                        {
                            "id": "CVE-2026-0002",
                            "shortDescription": {"text": "openssl issue"},
                            "properties": {"security-severity": "9.8"},
                        },
                    ]
                }
            },
            "results": [
                {"ruleId": "CVE-2026-0001"},
                {"ruleId": "CVE-2026-0002"},
            ],
        }
    ]
}


def run(
    tmp_path: Path, pip_audit: object, sarif: object | None = None
) -> tuple[subprocess.CompletedProcess[str], Path]:
    pa = tmp_path / "pip-audit.json"
    pa.write_text(json.dumps(pip_audit) if pip_audit is not None else "", "utf-8")
    out = tmp_path / "body.md"
    cmd = [sys.executable, str(SCRIPT), "--pip-audit", str(pa), "--out", str(out)]
    if sarif is not None:
        sf = tmp_path / "scout.sarif"
        sf.write_text(json.dumps(sarif), "utf-8")
        cmd += ["--scout-sarif", str(sf)]
    return subprocess.run(cmd, capture_output=True, text=True), out


def test_fixable_and_unfixable_are_separated(tmp_path: Path) -> None:
    proc, out = run(tmp_path, PIP_AUDIT_MIXED)
    assert proc.returncode == 0, proc.stderr
    body = out.read_text("utf-8")

    # The fixable advisory drives the report.
    assert "GHSA-qp9x-wp8f-qgjj" in body
    assert "7.0.0" in body
    assert "**1 fixable vulnerability**" in body

    # The unfixable one is present but demoted, and excluded from the count.
    assert "PYSEC-2025-183" in body
    assert "no fix available" in body
    assert "does not gate this issue" in body


def test_editable_skip_is_ignored(tmp_path: Path) -> None:
    _, out = run(tmp_path, PIP_AUDIT_MIXED)
    assert "compose-lint |" not in out.read_text("utf-8")


def test_clean_report_has_no_findings(tmp_path: Path) -> None:
    proc, out = run(tmp_path, {"dependencies": [], "fixes": []})
    assert proc.returncode == 0, proc.stderr
    assert "**0 fixable vulnerabilities**" in out.read_text("utf-8")
    assert "total=0" in proc.stdout


def test_image_cves_are_reported_with_severity_bands(tmp_path: Path) -> None:
    proc, out = run(tmp_path, {"dependencies": []}, SCOUT_SARIF)
    assert proc.returncode == 0, proc.stderr
    body = out.read_text("utf-8")
    assert "CVE-2026-0002" in body and "critical" in body
    assert "CVE-2026-0001" in body and "medium" in body
    # Critical sorts above medium.
    assert body.index("CVE-2026-0002") < body.index("CVE-2026-0001")
    # A medium image CVE counts: fixability gates, not severity.
    assert "**2 fixable vulnerabilities**" in body


def test_missing_pip_audit_report_fails_loudly(tmp_path: Path) -> None:
    out = tmp_path / "body.md"
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--pip-audit",
            str(tmp_path / "nope.json"),
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    assert "does not exist" in proc.stderr
    assert not out.exists(), "must not emit an all-clear body on scanner failure"


def test_empty_pip_audit_report_fails_loudly(tmp_path: Path) -> None:
    proc, out = run(tmp_path, None)
    assert proc.returncode == 1
    assert "is empty" in proc.stderr
    assert not out.exists()


def test_unexpected_pip_audit_shape_fails_loudly(tmp_path: Path) -> None:
    proc, out = run(tmp_path, {"unexpected": True})
    assert proc.returncode == 1
    assert "shape changed" in proc.stderr
    assert not out.exists()


def test_unexpected_sarif_shape_fails_loudly(tmp_path: Path) -> None:
    proc, out = run(tmp_path, {"dependencies": []}, {"not": "sarif"})
    assert proc.returncode == 1
    assert "shape changed" in proc.stderr
    assert not out.exists()


def test_report_states_it_applies_no_suppressions(tmp_path: Path) -> None:
    _, out = run(tmp_path, {"dependencies": []})
    assert "no `--ignore-vuln` suppressions" in out.read_text("utf-8")
