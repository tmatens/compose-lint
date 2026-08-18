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
        if step.get("uses") == "./":
            return step
    raise AssertionError("no `uses: ./` step in the ingestion workflow")


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
