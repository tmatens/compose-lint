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
import re
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


def test_a_statement_for_another_package_neither_adds_nor_hides_a_gap(
    tmp_path: Path,
) -> None:
    # The document also carries Debian base-image statements (#1365). The
    # check diffs pip's advisory list against the statement names, so a name
    # that is not a pip advisory must leave the result exactly as it was.
    vex = _vex("CVE-2025-8869", "CVE-2022-0563", "CVE-2010-4756")
    proc, out = run(tmp_path, CLEAN, vex=vex, osv=OSV_PIP, extra=FLOOR)
    assert proc.returncode == 0, proc.stderr
    body = out.read_text("utf-8")
    assert "**2 OpenVEX gaps**" in body
    assert "CVE-2022-0563" not in body and "CVE-2010-4756" not in body
    assert _outputs(tmp_path)["gaps"] == "2"


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


# --- Image findings with no fix -------------------------------------------
#
# The unfiltered scan, with the OpenVEX document applied, against the
# accepted list. `TODAY` is fixed so ages do not move with the calendar.

TODAY = "2026-11-24"
OPEN_ONE = {
    "findings": [
        {"id": "CVE-2019-1010022", "package": "glibc", "reason": "weaker mitigation"}
    ]
}


def _sarif(*ids: str, package: str = "glibc") -> dict[str, object]:
    purl = f"pkg:deb/debian/{package}@2.41-12%2Bdeb13u5?os_name=debian"
    message = f"Vulnerability    :X\nPackage          :{purl}\nFixed version    :-\n"
    return {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {"id": i, "properties": {"security-severity": "3.1"}}
                            for i in ids
                        ]
                    }
                },
                "results": [{"ruleId": i, "message": {"text": message}} for i in ids],
            }
        ]
    }


def run_image(
    tmp_path: Path,
    reported: list[str],
    *,
    fixable: list[str] | None = None,
    alerts: list[str] | None = None,
    accepted: object | None = None,
    vex: object | None = None,
    published: dict[str, str] | None = None,
    alerts_payload: object | None = None,
    extra: list[str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Run the report with the image-findings inputs.

    ``alerts`` defaults to ``reported``: both scans agree unless a test says
    otherwise. ``accepted`` defaults to ``OPEN_ONE`` when the scan reports its
    CVE and to an empty list when it does not, so a test about something else
    does not also trip the stale check. ``published`` maps a CVE to its OSV
    publication date; a CVE left out has no record, as when OSV answers 404.
    """
    if accepted is None:
        accepted = OPEN_ONE if "CVE-2019-1010022" in reported else {"findings": []}
    files = {
        "scout-all.sarif": _sarif(*reported),
        "open-findings.json": accepted,
        "scout-alerts.json": alerts_payload
        if alerts_payload is not None
        else {"rule_ids": reported if alerts is None else alerts},
    }
    for name, payload in files.items():
        (tmp_path / name).write_text(json.dumps(payload), "utf-8")
    records = tmp_path / "osv-image"
    records.mkdir()
    for cve, when in (published or {}).items():
        (records / f"{cve}.json").write_text(
            json.dumps({"id": cve, "published": when}), "utf-8"
        )
    args = [
        "--scout-all-sarif",
        str(tmp_path / "scout-all.sarif"),
        "--open-findings",
        str(tmp_path / "open-findings.json"),
        "--scout-alerts",
        str(tmp_path / "scout-alerts.json"),
        "--published-dir",
        str(records),
        "--today",
        TODAY,
        *FLOOR,
        *(extra or []),
    ]
    return run(
        tmp_path,
        CLEAN,
        _sarif(*(fixable or [])),
        vex=vex if vex is not None else VEX_ONE,
        osv=_osv(_advisory("PYSEC-2025-0001", "CVE-2025-8869", fixed=["25.3"])),
        extra=args,
    )


def test_an_accepted_finding_that_is_still_reported_is_quiet(tmp_path: Path) -> None:
    proc, out = run_image(tmp_path, ["CVE-2019-1010022"])
    assert proc.returncode == 0, proc.stderr
    assert "Nothing to decide. ✅" in out.read_text("utf-8")
    outputs = _outputs(tmp_path)
    assert outputs["undecided"] == "0"
    assert outputs["has_findings"] == "false"


def test_an_old_unstated_finding_opens_the_issue(tmp_path: Path) -> None:
    proc, out = run_image(
        tmp_path,
        ["CVE-2019-1010022", "CVE-2026-0009"],
        published={"CVE-2026-0009": "2026-11-10T08:00:00Z"},
    )
    assert proc.returncode == 0, proc.stderr
    body = out.read_text("utf-8")
    assert "**1 image finding to decide**" in body
    assert "| `CVE-2026-0009` | glibc | low | 2026-11-10 | 14 days |" in body
    outputs = _outputs(tmp_path)
    assert outputs["undecided"] == "1"
    assert outputs["has_findings"] == "true"
    assert outputs["title"].endswith("image findings to decide (1)")


def test_a_finding_younger_than_the_threshold_waits(tmp_path: Path) -> None:
    proc, out = run_image(
        tmp_path, ["CVE-2026-0009"], published={"CVE-2026-0009": "2026-11-11"}
    )
    assert proc.returncode == 0, proc.stderr
    body = out.read_text("utf-8")
    assert "`CVE-2026-0009` (published 13 days ago, under 14)" in body
    assert "does not gate this issue" in body
    assert _outputs(tmp_path)["has_findings"] == "false"


def test_the_threshold_is_a_parameter(tmp_path: Path) -> None:
    proc, _ = run_image(
        tmp_path,
        ["CVE-2026-0009"],
        published={"CVE-2026-0009": "2026-11-11"},
        extra=["--min-age-days", "13"],
    )
    assert proc.returncode == 0, proc.stderr
    assert _outputs(tmp_path)["undecided"] == "1"


def test_a_finding_with_no_publication_record_counts_as_old(tmp_path: Path) -> None:
    """An unknown age cannot be ruled out as recent, so it does not wait."""
    proc, out = run_image(tmp_path, ["CVE-2026-0009"])
    assert proc.returncode == 0, proc.stderr
    assert "| `CVE-2026-0009` | glibc | low | unknown | unknown |" in out.read_text(
        "utf-8"
    )
    assert _outputs(tmp_path)["undecided"] == "1"


def test_a_finding_only_one_scan_reports_waits(tmp_path: Path) -> None:
    proc, out = run_image(
        tmp_path,
        ["CVE-2026-0009"],
        alerts=[],
        published={"CVE-2026-0009": "2026-01-01"},
    )
    assert proc.returncode == 0, proc.stderr
    assert "`CVE-2026-0009` (seen by one scan only)" in out.read_text("utf-8")
    assert _outputs(tmp_path)["has_findings"] == "false"


def test_a_fixable_finding_is_left_to_the_fixable_table(tmp_path: Path) -> None:
    proc, out = run_image(
        tmp_path,
        ["CVE-2019-1010022", "CVE-2026-0009"],
        fixable=["CVE-2026-0009"],
        published={"CVE-2026-0009": "2026-01-01"},
    )
    assert proc.returncode == 0, proc.stderr
    assert "Nothing to decide. ✅" in out.read_text("utf-8")
    outputs = _outputs(tmp_path)
    assert outputs["count"] == "1"
    assert outputs["undecided"] == "0"


def test_a_reported_cve_that_has_a_statement_is_called_out(tmp_path: Path) -> None:
    """The scan ran with the document applied, so this is a statement that
    did not match, not a finding to accept."""
    proc, out = run_image(tmp_path, ["CVE-2025-8869"], accepted={"findings": []})
    assert proc.returncode == 0, proc.stderr
    body = out.read_text("utf-8")
    assert "the scanner did not apply it" in body and "`CVE-2025-8869`" in body
    assert _outputs(tmp_path)["undecided"] == "1"


@pytest.mark.parametrize(
    ("reported", "fixable", "alerts", "vex", "why"),
    [
        ([], [], [], None, "neither scan reports it any more"),
        (["CVE-2019-1010022"], ["CVE-2019-1010022"], None, None, "a fix is now"),
        (
            ["CVE-2019-1010022"],
            [],
            None,
            _vex("CVE-2019-1010022"),
            "also has a statement",
        ),
    ],
)
def test_an_accepted_entry_that_no_longer_holds_is_stale(
    tmp_path: Path,
    reported: list[str],
    fixable: list[str],
    alerts: list[str] | None,
    vex: object | None,
    why: str,
) -> None:
    proc, out = run_image(
        tmp_path, reported, fixable=fixable, alerts=alerts, vex=vex, accepted=OPEN_ONE
    )
    assert proc.returncode == 0, proc.stderr
    body = out.read_text("utf-8")
    assert "| `CVE-2019-1010022` | glibc |" in body and why in body
    assert _outputs(tmp_path)["has_findings"] == "true"


@pytest.mark.parametrize(
    ("reported", "alerts"),
    [([], ["CVE-2019-1010022"]), (["CVE-2019-1010022"], [])],
)
def test_an_accepted_entry_one_scan_still_reports_is_not_stale(
    tmp_path: Path, reported: list[str], alerts: list[str]
) -> None:
    proc, out = run_image(tmp_path, reported, alerts=alerts, accepted=OPEN_ONE)
    assert proc.returncode == 0, proc.stderr
    assert "Nothing to decide. ✅" in out.read_text("utf-8")


@pytest.mark.parametrize(
    "accepted",
    [
        {"findings": [{"id": "CVE-2019-1010022", "package": "glibc"}]},
        {"findings": [{"id": "CVE-2019-1010022", "package": "glibc", "reason": " "}]},
        {"findings": OPEN_ONE["findings"] * 2},
        {"entries": []},
    ],
)
def test_a_malformed_open_findings_list_fails_loudly(
    tmp_path: Path, accepted: object
) -> None:
    proc, out = run_image(tmp_path, [], accepted=accepted)
    assert proc.returncode == 1
    assert "open findings" in proc.stderr
    assert not out.exists()


def test_a_malformed_alert_list_fails_loudly(tmp_path: Path) -> None:
    proc, out = run_image(tmp_path, [], alerts_payload=["CVE-2019-1010022"])
    assert proc.returncode == 1
    assert "rule_ids" in proc.stderr
    assert not out.exists()


def test_a_publication_record_without_a_date_fails_loudly(tmp_path: Path) -> None:
    proc, out = run_image(tmp_path, ["CVE-2026-0009"], published={"CVE-2026-0009": ""})
    assert proc.returncode == 1
    assert "published" in proc.stderr
    assert not out.exists()


def test_the_image_inputs_must_be_given_together(tmp_path: Path) -> None:
    proc, _ = run(
        tmp_path, CLEAN, SCOUT_SARIF, extra=["--open-findings", "open-findings.json"]
    )
    assert proc.returncode == 2
    assert "must be given together" in proc.stderr


def test_without_the_image_inputs_the_section_is_omitted(tmp_path: Path) -> None:
    proc, out = run(tmp_path, CLEAN, SCOUT_SARIF)
    assert proc.returncode == 0, proc.stderr
    assert "Image findings with no fix" not in out.read_text("utf-8")


def test_the_real_open_findings_list_parses_and_matches_the_docs(
    tmp_path: Path,
) -> None:
    """The shipped list is the input in production, and docs/verifying.md
    tells readers the same thing in prose: hold the two together, and both
    to the OpenVEX document."""
    real = json.loads((REPO_ROOT / ".vex" / "open-findings.json").read_text("utf-8"))
    ids = [f["id"] for f in real["findings"]]
    proc, out = run_image(tmp_path, ids, accepted=real)
    assert proc.returncode == 0, proc.stderr
    assert "Nothing to decide. ✅" in out.read_text("utf-8")

    vex = json.loads(
        (REPO_ROOT / ".vex" / "compose-lint.openvex.json").read_text("utf-8")
    )
    stated = {st["vulnerability"]["name"] for st in vex["statements"]}
    assert not stated & set(ids), "a finding is both accepted as open and stated"

    doc = (REPO_ROOT / "docs" / "verifying.md").read_text("utf-8")
    section = doc.split("## What a scan of the image reports", 1)[1].split("\n## ", 1)[
        0
    ]
    rows = re.findall(r"^\| \[(CVE-\d+-\d+)\]", section, re.MULTILINE)
    assert rows == ids, "docs/verifying.md lists different open findings"
    pip = sum("subcomponents" in st["products"][0] for st in vex["statements"])
    total = len(vex["statements"])
    assert (
        f"carries {total} statements: {total - pip} for CVEs in the base image's "
        f"Debian packages and {pip} for pip"
    ) in section, "docs/verifying.md states different statement counts"
