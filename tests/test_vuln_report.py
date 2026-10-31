"""Tests for the rolling fixable-vulnerability report (scripts/vuln_report.py).

Runs the actual script as a subprocess — the same entry point CI invokes —
over synthetic pip-audit and Docker Scout payloads.

The behaviour that matters most here is the *negative* case: a missing or
malformed scanner report must fail loudly rather than render an empty
"nothing to fix" body, which would read as an all-clear.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

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


def _osv(*vulns: dict[str, object], **extra: object) -> dict[str, object]:
    return {"vulns": list(vulns), **extra}


def _advisory(
    osv_id: str,
    *cves: str,
    fixed: list[str] | None = None,
    published: str = "2026-05-01T00:00:00Z",
    package: str = "pip",
    **extra: object,
) -> dict[str, object]:
    events: list[dict[str, str]] = [{"introduced": "0"}]
    events += [{"fixed": f} for f in (fixed or [])]
    return {
        "id": osv_id,
        "aliases": list(cves),
        "published": published,
        "summary": f"{osv_id} summary",
        "affected": [
            {
                "package": {"name": package, "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ],
        **extra,
    }


def _vex(*names: str) -> dict[str, object]:
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "version": 5,
        "statements": [
            {"vulnerability": {"name": n}, "status": "not_affected"} for n in names
        ],
    }


# The six-statement shape of the real document: one covered advisory, one
# published and fixed between releases (the #1040 miss), one with no fix,
# one so old no published tag can carry an affected pip, one withdrawn.
OSV_PIP = _osv(
    _advisory(
        "PYSEC-2025-0001",
        "CVE-2025-8869",
        fixed=["25.3"],
        published="2025-09-25T00:00:00Z",
    ),
    _advisory(
        "GHSA-new1-new1-new1",
        "CVE-2026-13346",
        fixed=["26.2"],
        published="2026-07-29T00:00:00Z",
    ),
    _advisory("PYSEC-2026-0002", "CVE-2026-77777", published="2026-08-01T00:00:00Z"),
    _advisory(
        "PYSEC-2019-0001",
        "CVE-2019-20916",
        fixed=["19.2"],
        published="2019-09-01T00:00:00Z",
    ),
    _advisory(
        "PYSEC-2026-0003",
        "CVE-2026-55555",
        fixed=["26.4"],
        withdrawn="2026-09-01T00:00:00Z",
    ),
)
VEX_ONE = _vex("CVE-2025-8869")


def run(
    tmp_path: Path,
    pip_audit: object,
    sarif: object | None = None,
    *,
    vex: object | None = None,
    osv: object | str | None = None,
    extra: list[str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    pa = tmp_path / "pip-audit.json"
    pa.write_text(json.dumps(pip_audit) if pip_audit is not None else "", "utf-8")
    out = tmp_path / "body.md"
    cmd = [sys.executable, str(SCRIPT), "--pip-audit", str(pa), "--out", str(out)]
    if sarif is not None:
        sf = tmp_path / "scout.sarif"
        sf.write_text(json.dumps(sarif), "utf-8")
        cmd += ["--scout-sarif", str(sf)]
    if vex is not None:
        vf = tmp_path / "compose-lint.openvex.json"
        vf.write_text(json.dumps(vex), "utf-8")
        cmd += ["--vex", str(vf)]
    if osv is not None:
        of = tmp_path / "osv-pip.json"
        of.write_text(osv if isinstance(osv, str) else json.dumps(osv), "utf-8")
        cmd += ["--osv", str(of)]
    cmd += extra or []
    env = {**os.environ, "GITHUB_OUTPUT": str(tmp_path / "outputs.txt")}
    return subprocess.run(cmd, capture_output=True, text=True, env=env), out


def _outputs(tmp_path: Path) -> dict[str, str]:
    lines = (tmp_path / "outputs.txt").read_text("utf-8").splitlines()
    return dict(line.split("=", 1) for line in lines)


CLEAN: dict[str, object] = {"dependencies": []}
FLOOR = ["--pip-floor", "25.1"]


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


# --- OpenVEX completeness (#1040) ------------------------------------------


def test_vex_gaps_are_the_in_scope_advisories_no_statement_names(
    tmp_path: Path,
) -> None:
    proc, out = run(tmp_path, CLEAN, vex=VEX_ONE, osv=OSV_PIP, extra=FLOOR)
    assert proc.returncode == 0, proc.stderr
    body = out.read_text("utf-8")
    # Published and fixed between releases, never seen by a scanner: the miss.
    assert "CVE-2026-13346" in body and "26.2" in body
    # No fix at all is still in scope.
    assert "CVE-2026-77777" in body
    # Covered by an existing statement.
    assert "`CVE-2025-8869`" not in body
    # Every fix at or below the floor: no published tag retains a pip that old.
    assert "CVE-2019-20916" not in body
    # Withdrawn advisories are not gaps.
    assert "CVE-2026-55555" not in body
    assert "**2 OpenVEX gaps**" in body
    outputs = _outputs(tmp_path)
    assert outputs["has_findings"] == "true"
    assert outputs["gaps"] == "2"
    assert outputs["count"] == "0"
    assert outputs["title"] == "Fixable vulnerabilities (0), OpenVEX gaps (2)"


def test_a_gap_alone_opens_the_issue_and_the_body_says_what_to_do(
    tmp_path: Path,
) -> None:
    proc, out = run(tmp_path, CLEAN, vex=VEX_ONE, osv=OSV_PIP, extra=FLOOR)
    assert proc.returncode == 0, proc.stderr
    body = out.read_text("utf-8")
    assert "vulnerable_code_not_present" in body
    assert "docs/RELEASING.md" in body
    assert "fix it instead" in body


def test_a_complete_vex_document_is_reported_as_such(tmp_path: Path) -> None:
    vex = _vex("CVE-2025-8869", "CVE-2026-13346", "CVE-2026-77777")
    proc, out = run(tmp_path, CLEAN, vex=vex, osv=OSV_PIP, extra=FLOOR)
    assert proc.returncode == 0, proc.stderr
    body = out.read_text("utf-8")
    assert "Complete. ✅" in body
    # Says what it compared: three in scope above the floor.
    assert "above pip 25.1 (3)" in body
    outputs = _outputs(tmp_path)
    assert outputs["has_findings"] == "false"
    assert outputs["title"] == "Fixable vulnerabilities (0)"


def test_coverage_counts_whichever_identifier_the_statement_uses(
    tmp_path: Path,
) -> None:
    # Statement names the GHSA, OSV's primary id is the PYSEC, the CVE is an alias.
    osv = _osv(
        _advisory(
            "PYSEC-2026-9", "CVE-2026-13346", "GHSA-aaaa-bbbb-cccc", fixed=["26.2"]
        )
    )
    proc, out = run(
        tmp_path, CLEAN, vex=_vex("GHSA-aaaa-bbbb-cccc"), osv=osv, extra=FLOOR
    )
    assert proc.returncode == 0, proc.stderr
    assert "Complete. ✅" in out.read_text("utf-8")


def test_vex_aliases_also_count_as_coverage(tmp_path: Path) -> None:
    vex = {
        "statements": [
            {
                "vulnerability": {"name": "GHSA-xxxx", "aliases": ["CVE-2026-13346"]},
                "status": "not_affected",
            }
        ]
    }
    osv = _osv(_advisory("PYSEC-2026-9", "CVE-2026-13346", fixed=["26.2"]))
    proc, out = run(tmp_path, CLEAN, vex=vex, osv=osv, extra=FLOOR)
    assert proc.returncode == 0, proc.stderr
    assert "Complete. ✅" in out.read_text("utf-8")


def test_without_a_floor_every_historical_advisory_is_in_scope(tmp_path: Path) -> None:
    proc, out = run(tmp_path, CLEAN, vex=VEX_ONE, osv=OSV_PIP)
    assert proc.returncode == 0, proc.stderr
    assert "CVE-2019-20916" in out.read_text("utf-8")


def test_an_unparseable_fix_version_keeps_the_advisory(tmp_path: Path) -> None:
    osv = _osv(_advisory("PYSEC-2026-8", "CVE-2026-11111", fixed=["not-a-version"]))
    proc, out = run(tmp_path, CLEAN, vex=VEX_ONE, osv=osv, extra=FLOOR)
    assert proc.returncode == 0, proc.stderr
    assert "CVE-2026-11111" in out.read_text("utf-8")


def test_a_gap_without_a_cve_alias_is_named_by_its_osv_id(tmp_path: Path) -> None:
    osv = _osv(_advisory("PYSEC-2026-7", fixed=["26.5"]))
    proc, out = run(tmp_path, CLEAN, vex=VEX_ONE, osv=osv, extra=FLOOR)
    assert proc.returncode == 0, proc.stderr
    assert "`PYSEC-2026-7`" in out.read_text("utf-8")


def test_affected_entries_for_other_packages_do_not_count_as_fixes(
    tmp_path: Path,
) -> None:
    # Only a setuptools range carries a fix; for pip the advisory is unfixed, in scope.
    osv = _osv(
        _advisory(
            "PYSEC-2026-6", "CVE-2026-22222", fixed=["80.0"], package="setuptools"
        )
    )
    proc, out = run(tmp_path, CLEAN, vex=VEX_ONE, osv=osv, extra=FLOOR)
    assert proc.returncode == 0, proc.stderr
    assert "CVE-2026-22222" in out.read_text("utf-8")


def test_a_paginated_osv_response_fails_loudly(tmp_path: Path) -> None:
    osv = _osv(
        _advisory("PYSEC-2026-5", "CVE-2026-33333", fixed=["26.5"]),
        next_page_token="abc",
    )
    proc, _ = run(tmp_path, CLEAN, vex=VEX_ONE, osv=osv, extra=FLOOR)
    assert proc.returncode == 1
    assert "next_page_token" in proc.stderr


def test_an_empty_osv_list_fails_loudly(tmp_path: Path) -> None:
    proc, _ = run(tmp_path, CLEAN, vex=VEX_ONE, osv=_osv(), extra=FLOOR)
    assert proc.returncode == 1
    assert "broken, not clean" in proc.stderr


@pytest.mark.parametrize("payload", ["", "{}", '{"error": "bad request"}', "[]"])
def test_a_malformed_osv_response_fails_loudly(tmp_path: Path, payload: str) -> None:
    proc, _ = run(tmp_path, CLEAN, vex=VEX_ONE, osv=payload, extra=FLOOR)
    assert proc.returncode == 1
    assert "::error::" in proc.stderr


def test_a_malformed_vex_document_fails_loudly(tmp_path: Path) -> None:
    proc, _ = run(
        tmp_path, CLEAN, vex={"statements": [{"status": "not_affected"}]}, osv=OSV_PIP
    )
    assert proc.returncode == 1
    assert "vulnerability.name" in proc.stderr


def test_vex_and_osv_must_be_given_together(tmp_path: Path) -> None:
    proc, _ = run(tmp_path, CLEAN, vex=VEX_ONE)
    assert proc.returncode == 2
    assert "together" in proc.stderr


def test_the_real_vex_document_parses(tmp_path: Path) -> None:
    """The shipped document is the input in production; prove the parser reads it."""
    real = json.loads(
        (REPO_ROOT / ".vex" / "compose-lint.openvex.json").read_text("utf-8")
    )
    names = [st["vulnerability"]["name"] for st in real["statements"]]
    osv = _osv(
        *(_advisory(f"PYSEC-{i}", n, fixed=["99.0"]) for i, n in enumerate(names))
    )
    proc, out = run(tmp_path, CLEAN, vex=real, osv=osv, extra=FLOOR)
    assert proc.returncode == 0, proc.stderr
    assert "Complete. ✅" in out.read_text("utf-8")


def test_a_git_range_commit_hash_is_not_a_fix_version(tmp_path: Path) -> None:
    """CVE-2019-20916 as OSV publishes it: fixed in 19.2 by version, and by a
    commit hash in a GIT range. The hash must not keep an advisory every
    published tag is past; the first live run listed it as a gap."""
    adv = _advisory(
        "PYSEC-2020-0001",
        "CVE-2019-20916",
        fixed=["19.2"],
        published="2020-09-04T00:00:00Z",
    )
    adv["affected"] = [
        *adv["affected"],  # type: ignore[misc]
        {
            "package": {"name": "pip", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "GIT",
                    "repo": "https://github.com/pypa/pip",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "a4c735b14a62f9cb864533808ac63936704f2ace"},
                    ],
                }
            ],
        },
    ]
    proc, out = run(tmp_path, CLEAN, vex=VEX_ONE, osv=_osv(adv), extra=FLOOR)
    assert proc.returncode == 0, proc.stderr
    assert "CVE-2019-20916" not in out.read_text("utf-8")


def test_an_advisory_with_only_a_git_range_stays_in_scope(tmp_path: Path) -> None:
    adv = _advisory("PYSEC-2026-0004", "CVE-2026-44444")
    adv["affected"] = [
        {
            "package": {"name": "pip", "ecosystem": "PyPI"},
            "ranges": [
                {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "deadbeef"}]}
            ],
        }
    ]
    proc, out = run(tmp_path, CLEAN, vex=VEX_ONE, osv=_osv(adv), extra=FLOOR)
    assert proc.returncode == 0, proc.stderr
    assert "CVE-2026-44444" in out.read_text("utf-8")


def test_details_stand_in_for_a_missing_summary(tmp_path: Path) -> None:
    adv = _advisory("PYSEC-2026-0005", "CVE-2026-66666", fixed=["26.9"])
    del adv["summary"]
    adv["details"] = (
        "pip resolved the wrong index URL when a mirror was set.\n\n"
        "Longer text follows."
    )
    proc, out = run(tmp_path, CLEAN, vex=VEX_ONE, osv=_osv(adv), extra=FLOOR)
    assert proc.returncode == 0, proc.stderr
    body = out.read_text("utf-8")
    assert "pip resolved the wrong index URL" in body
    assert "Longer text follows" not in body


# --- GitHub Actions advisories (zizmor known-vulnerable-actions) -----------


def _zizmor_finding(
    advisory: str,
    action: str,
    pinned: str,
    row: int,
    *,
    fix: str | None = "upgrade it",
    ident: str = "known-vulnerable-actions",
    ignored: bool = False,
    path: str = ".github/workflows/publish.yml",
) -> dict[str, object]:
    """One finding in the shape `zizmor --format json` emits (1.30)."""
    return {
        "ident": ident,
        "desc": "action has a known vulnerability",
        "determinations": {"confidence": "High", "severity": "High"},
        "ignored": ignored,
        "fixes": [{"title": fix, "disposition": "unsafe"}] if fix else [],
        "locations": [
            {
                "symbolic": {
                    "key": {"Local": {"verbatim_path": path}},
                    "annotation": advisory,
                    "kind": "Primary",
                },
                "concrete": {
                    "location": {"start_point": {"row": row, "column": 8}},
                    "feature": f"uses: {action}@{'a' * 40}",
                    "comments": [f"# {pinned}"],
                },
            }
        ],
    }


def run_zizmor(
    tmp_path: Path, findings: object | str
) -> tuple[subprocess.CompletedProcess[str], Path]:
    zf = tmp_path / "zizmor.json"
    zf.write_text(
        findings if isinstance(findings, str) else json.dumps(findings), "utf-8"
    )
    return run(tmp_path, CLEAN, extra=["--zizmor", str(zf)])


PUBLISH_FIX = "upgrade pypa/gh-action-pypi-publish to v1.14.3"


def test_an_action_advisory_with_a_fix_opens_the_issue(tmp_path: Path) -> None:
    proc, out = run_zizmor(
        tmp_path,
        [
            _zizmor_finding(
                "GHSA-5xjx-3w67-w9x9",
                "pypa/gh-action-pypi-publish",
                "v1.14.2",
                285,
                fix=PUBLISH_FIX,
            ),
            _zizmor_finding(
                "GHSA-5xjx-3w67-w9x9",
                "pypa/gh-action-pypi-publish",
                "v1.14.2",
                624,
                fix=PUBLISH_FIX,
            ),
        ],
    )
    assert proc.returncode == 0, proc.stderr
    body = out.read_text("utf-8")
    # Two uses of one action under one advisory are one row, not two.
    assert "**1 fixable vulnerability**" in body
    assert (
        "| `GHSA-5xjx-3w67-w9x9` | `pypa/gh-action-pypi-publish` | v1.14.2 | "
        f"{PUBLISH_FIX} | .github/workflows/publish.yml:286, "
        ".github/workflows/publish.yml:625 |"
    ) in body
    assert "actions=1" in proc.stdout
    outputs = _outputs(tmp_path)
    assert outputs["has_findings"] == "true"
    assert outputs["title"] == "Fixable vulnerabilities (1)"


def test_an_action_advisory_without_a_fix_does_not_gate(tmp_path: Path) -> None:
    proc, out = run_zizmor(
        tmp_path,
        [_zizmor_finding("GHSA-nofx-nofx-nofx", "acme/tool", "v2", 9, fix=None)],
    )
    assert proc.returncode == 0, proc.stderr
    body = out.read_text("utf-8")
    assert "**0 fixable vulnerabilities**" in body
    assert "`GHSA-nofx-nofx-nofx` (`acme/tool`)" in body
    assert "does not gate this issue" in body
    assert _outputs(tmp_path)["has_findings"] == "false"


def test_other_zizmor_audits_are_left_to_ci(tmp_path: Path) -> None:
    proc, out = run_zizmor(
        tmp_path,
        [
            _zizmor_finding(
                "ignored-annotation", "acme/tool", "v1", 3, ident="unpinned-uses"
            )
        ],
    )
    assert proc.returncode == 0, proc.stderr
    body = out.read_text("utf-8")
    assert "## GitHub Actions" in body
    assert "acme/tool" not in body
    assert "**0 fixable vulnerabilities**" in body


def test_an_action_advisory_the_config_ignores_is_still_reported(
    tmp_path: Path,
) -> None:
    # Same anti-rot property as running pip-audit unsuppressed.
    _, out = run_zizmor(
        tmp_path,
        [_zizmor_finding("GHSA-ign0-ign0-ign0", "acme/tool", "v1", 3, ignored=True)],
    )
    assert "`GHSA-ign0-ign0-ign0`" in out.read_text("utf-8")


def test_without_a_zizmor_report_the_actions_section_is_omitted(
    tmp_path: Path,
) -> None:
    _, out = run(tmp_path, CLEAN)
    assert "## GitHub Actions" not in out.read_text("utf-8")


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ("", "is empty"),
        ("not json", "not valid JSON"),
        ('{"findings": []}', "not a list of findings"),
        ('[{"desc": "no ident"}]', "without an 'ident'"),
    ],
)
def test_a_malformed_zizmor_report_fails_loudly(
    tmp_path: Path, payload: str, message: str
) -> None:
    proc, out = run_zizmor(tmp_path, payload)
    assert proc.returncode == 1
    assert message in proc.stderr
    assert not out.exists(), "must not emit an all-clear body on scanner failure"
