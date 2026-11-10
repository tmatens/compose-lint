"""The SARIF ingestion probe must keep failing for one reason only (#610).

`.github/workflows/sarif-ingestion.yml` uploads a compose-lint SARIF to
Code Scanning so that a document GitHub rejects fails *our* run instead of
a consumer's. That only works if the lint itself exits 0 — otherwise the
action step goes red on findings, and the obvious fix (`continue-on-error`)
would swallow the upload failure the job exists to detect.

That contract depends on the fixtures and the rule set, both of which
change. A new critical-severity rule flagging any probe fixture breaks it,
and the workflow runs post-merge and weekly, so the breakage would surface
a week after the PR that caused it. These tests move that signal onto the
PR, and read the workflow rather than a copy of it so the two cannot drift.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "sarif-ingestion.yml"


def _upload_step() -> dict[str, Any]:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["ingest"]["steps"]
    for step in steps:
        if step.get("uses") == "$/":
            return step
    raise AssertionError("no `uses: $/` step in the ingestion workflow")


def _probe_args() -> tuple[list[str], str, str]:
    with_ = _upload_step()["with"]
    return with_["files"].split(), with_["config"], with_["fail-on"]


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "compose_lint", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_the_probe_lint_exits_zero() -> None:
    """A non-zero lint makes the upload assertion unreadable.

    If this fails because a new rule flags a probe fixture at critical,
    the fix is to extend tests/smoke/sarif-probe-config.yml — never to add
    `continue-on-error` to the workflow step.
    """
    files, config, fail_on = _probe_args()
    proc = _run(["check", "--config", config, "--fail-on", fail_on, *files])
    assert proc.returncode == 0, (
        "the SARIF ingestion probe's lint must exit 0 so that only an upload "
        f"failure can fail that job; got {proc.returncode}\n"
        f"{proc.stdout}\n{proc.stderr}"
    )


def test_the_probe_sarif_stays_worth_uploading() -> None:
    """A probe that degrades to one trivial result stops proving anything.

    The rejections this job exists to catch are constructs: several
    artifactLocations, more than one `level`, a suppression's
    `justification`. A document carrying none of them can be accepted while
    a real one is not.
    """
    files, config, fail_on = _probe_args()
    proc = _run(
        ["check", "--config", config, "--fail-on", fail_on, "--format", "sarif", *files]
    )
    assert proc.returncode == 0, proc.stderr
    run = json.loads(proc.stdout)["runs"][0]
    results = run["results"]

    assert results, "the probe produced no SARIF results"

    locations = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in results
    }
    assert len(locations) > 1, (
        f"probe covers one artifact only ({locations}); a missing "
        "artifactLocation base would not show up"
    )
    assert len({r["level"] for r in results}) > 1, (
        "probe exercises a single SARIF level; a level GitHub rejects would not show up"
    )
    assert any(r.get("suppressions") for r in results), (
        "probe carries no suppressed result, so its `justification` construct "
        "is never ingested"
    )

    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids)), (
        f"duplicate ruleId in the probe document: {sorted(rule_ids)} — GitHub "
        "rejects these, and it would be found in the consumer's job"
    )


# --- What Code Scanning makes of a suppressed result (#1207 review) ---


def _probe_script() -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "verify_sarif_ingestion",
        REPO_ROOT / "scripts" / "verify_sarif_ingestion.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_suppression_report_names_all_three_outcomes() -> None:
    classify = _probe_script().classify_suppressed
    other = {"rule": {"id": "CL-0001"}, "state": "open"}
    assert classify([other], "CL-0002").startswith("absent:")
    dismissed = {
        "rule": {"id": "CL-0002"},
        "state": "dismissed",
        "dismissed_reason": "won't fix",
    }
    assert classify([other, dismissed], "CL-0002").startswith("dismissed:")
    opened = {"rule": {"id": "CL-0002"}, "state": "open"}
    assert classify([opened, dismissed], "CL-0002").startswith("dismissed/open:")
    assert classify([opened], "CL-0002").startswith("open:")


def test_the_reported_rule_is_one_the_probe_suppresses() -> None:
    """The report means something only if every result of that rule is suppressed."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    runs = [step.get("run", "") for step in workflow["jobs"]["ingest"]["steps"]]
    reported = [
        run.split("--report-suppressed", 1)[1].split()[0]
        for run in runs
        if "--report-suppressed" in run
    ]
    assert reported, "no verify step reports on a suppressed rule"
    _files, config, _fail_on = _probe_args()
    rules = yaml.safe_load((REPO_ROOT / config).read_text(encoding="utf-8"))["rules"]
    for rule in reported:
        assert rules.get(rule, {}).get("enabled") is False, (
            f"{rule} is not disabled in {config}, so its results are not all suppressed"
        )
