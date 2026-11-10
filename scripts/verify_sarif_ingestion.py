#!/usr/bin/env python3
"""Prove GitHub actually ingested a compose-lint SARIF (#610).

``tests/test_sarif.py`` asserts the document's shape against the same
mental model that produced it. SARIF rejections are the failures that
model cannot see: a duplicate ``ruleId``, an out-of-range region, a
missing ``artifactLocation`` base, a ``level`` GitHub does not accept.
Those surface in the *consumer's* job — historically a user's workflow,
which is the worst place to learn about it.

``upload-sarif`` failing is the first half of the proof, and it is the
half the workflow gets for free. This script is the second half: an
accepted POST is not ingestion. It waits for an analysis attributed to
this run's commit and asserts it produced results, then that alerts are
actually queryable.

``cleanup`` is the other half of being a good citizen. The findings come
from fixtures that are deliberately insecure, and this repo already
refuses to let them near its alert set — ``ci.yml``'s action smoke sets
``upload-sarif: "false"`` for exactly that reason. So the probe deletes
its own analysis afterwards rather than leaving fixture findings in the
repo's Code Scanning.

``verify`` optionally takes ``--expect-path SUBSTRING``, which asserts an
ingested alert is located in a file whose path contains SUBSTRING. That is
how the overlay probe (#631) answers a question no local test can: when a
finding's evidence lives in a ``compose.override.yml`` — a file Compose
merges but which is usually gitignored, and so absent from the repository —
does Code Scanning keep the result, or silently discard a location it cannot
resolve? If it discards it, pointing SARIF at the contributing file is worse
in practice than naming the base and attaching the overlay as a related
location, and only GitHub can settle which.

``verify`` also optionally takes ``--report-suppressed RULE``, which reports
what Code Scanning made of that rule's results when every one of them is
suppressed in the SARIF (``suppressions[]`` with a ``justification``): an open
alert, a dismissed one, or none. GitHub's SARIF documentation does not list
``suppressions`` among the properties it uses, and the answer decides whether a
``.compose-lint.yml`` exclusion hides anything in Code Scanning. It is a
measurement, not an assertion: any outcome passes, and the answer is printed
and written to the job summary.

Usage:
    python scripts/verify_sarif_ingestion.py verify [--expect-path SUBSTRING]
        [--report-suppressed RULE]
    python scripts/verify_sarif_ingestion.py cleanup

Reads GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_REF, GITHUB_SHA.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
TOOL = "compose-lint"

TOKEN = os.environ.get("GITHUB_TOKEN", "")
REPO = os.environ.get("GITHUB_REPOSITORY", "")
REF = os.environ.get("GITHUB_REF", "")
SHA = os.environ.get("GITHUB_SHA", "")

# The alert states the REST API filters on. Listing each one, rather than
# relying on what an unfiltered query returns, makes a dismissed alert as
# visible to the report below as an open one.
ALERT_STATES = ("open", "dismissed", "fixed", "closed")


def classify_suppressed(alerts: list[dict[str, object]], rule: str) -> str:
    """One line saying what Code Scanning made of ``rule``'s suppressed results.

    ``alerts`` is every alert the run produced, in any state. Pure, so the
    three outcomes are testable without the network.
    """

    def rule_id(alert: dict[str, object]) -> str:
        meta = alert.get("rule")
        return str(meta.get("id")) if isinstance(meta, dict) else ""

    mine = [a for a in alerts if rule_id(a) == rule]
    if not mine:
        return (
            f"absent: no alert for {rule}. Code Scanning dropped the suppressed "
            "results, so an exclusion hides the finding there."
        )
    states = sorted({str(a.get("state")) for a in mine})
    if states == ["dismissed"]:
        reasons = sorted({str(a.get("dismissed_reason")) for a in mine})
        return (
            f"dismissed: {len(mine)} alert(s) for {rule}, dismissed_reason="
            f"{', '.join(reasons)}. Code Scanning honours SARIF suppressions."
        )
    return (
        f"{'/'.join(states)}: {len(mine)} alert(s) for {rule}. Code Scanning "
        "ignores SARIF suppressions, so an exclusion does not hide the alert."
    )


def call(method: str, path: str, *, params: dict[str, str] | None = None) -> object:
    url = f"{API}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", f"Bearer {TOKEN}")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read()
    return json.loads(body) if body else None


def our_analyses() -> list[dict[str, object]]:
    """Analyses this run produced — matched on tool *and* commit."""
    try:
        found = call(
            "GET",
            f"/repos/{REPO}/code-scanning/analyses",
            params={"tool_name": TOOL, "ref": REF, "per_page": "100"},
        )
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise
    assert isinstance(found, list)
    return [a for a in found if a.get("commit_sha") == SHA]


def report_suppressed(rule: str) -> None:
    """Print, and add to the job summary, how ``rule``'s suppressed results landed."""
    # A measurement, so nothing here may fail the ingestion job: a state the
    # API rejects is skipped with a warning rather than raised.
    alerts: dict[int, dict[str, object]] = {}
    for state in ALERT_STATES:
        try:
            found = call(
                "GET",
                f"/repos/{REPO}/code-scanning/alerts",
                params={
                    "tool_name": TOOL,
                    "ref": REF,
                    "state": state,
                    "per_page": "100",
                },
            )
        except urllib.error.HTTPError as exc:
            print(f"::warning::alerts query for state={state} failed (HTTP {exc.code})")
            continue
        if not isinstance(found, list):
            continue
        for alert in found:
            alerts[int(alert["number"])] = alert
    line = (
        f"Suppressed {rule} results: {classify_suppressed(list(alerts.values()), rule)}"
    )
    print(f"::notice::{line}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"{line}\n")


def verify(expect_path: str | None = None, report_rule: str | None = None) -> int:
    # `upload-sarif` waits for processing, so an analysis should already
    # exist; alert indexing can still trail it by a few seconds.
    analyses: list[dict[str, object]] = []
    for attempt in range(1, 7):
        analyses = our_analyses()
        if analyses:
            break
        print(f"Attempt {attempt}: no compose-lint analysis for {SHA[:8]} yet; sleeping 10s...")
        time.sleep(10)

    if not analyses:
        print(
            f"::error::GitHub accepted the upload but produced no compose-lint "
            f"analysis for {SHA} on {REF} after ~60s. The POST succeeding is not "
            f"ingestion — this is the failure mode the job exists to catch."
        )
        return 1

    total = sum(int(a.get("results_count") or 0) for a in analyses)
    for a in analyses:
        print(
            f"analysis {a['id']}: category={a.get('category')!r} "
            f"results={a.get('results_count')} warning={a.get('warning')!r}"
        )
    if total == 0:
        print(
            "::error::The analysis ingested with zero results. The probe fixtures "
            "produce findings, so an empty analysis means GitHub discarded every "
            "result — a semantic rejection that does not fail the upload step."
        )
        return 1

    alerts = call(
        "GET",
        f"/repos/{REPO}/code-scanning/alerts",
        params={"tool_name": TOOL, "ref": REF, "per_page": "100"},
    )
    assert isinstance(alerts, list)
    if not alerts:
        print(
            "::error::The analysis reports results but no alert is queryable for "
            f"tool_name={TOOL}. Ingestion did not complete."
        )
        return 1

    rules = sorted({str(a["rule"]["id"]) for a in alerts})
    print(f"\nGitHub ingested {total} result(s); {len(alerts)} alert(s) queryable.")
    print(f"Rules that survived ingestion: {', '.join(rules)}")

    if expect_path is not None:
        located = sorted(
            {
                str(
                    (a.get("most_recent_instance") or {})
                    .get("location", {})
                    .get("path", "")
                )
                for a in alerts
            }
        )
        print(f"Alert locations: {', '.join(p for p in located if p)}")
        if not any(expect_path in path for path in located):
            print(
                f"::error::No ingested alert is located in a path containing "
                f"{expect_path!r}. GitHub kept the analysis but dropped the "
                f"results whose artifactLocation names a file that is not in "
                f"the repository. SARIF should then name the base file and "
                f"carry the overlay as a relatedLocation instead (#631)."
            )
            return 1
        print(f"Results located in {expect_path!r} survived ingestion.")
    if report_rule is not None:
        report_suppressed(report_rule)
    return 0


def cleanup() -> int:
    """Delete this run's analyses so fixture findings do not linger."""
    remaining = our_analyses()
    if not remaining:
        print("No probe analysis to clean up.")
        return 0

    deleted = 0
    for analysis in remaining:
        # Belt and braces before a destructive call on a security surface:
        # the query already filters by tool, and this refuses anything that
        # is not ours even if that filter ever changes meaning.
        name = str((analysis.get("tool") or {}).get("name", ""))
        if name != TOOL or analysis.get("commit_sha") != SHA:
            print(f"::warning::refusing to delete analysis {analysis['id']} (tool={name!r})")
            continue
        try:
            call(
                "DELETE",
                f"/repos/{REPO}/code-scanning/analyses/{analysis['id']}",
                params={"confirm_delete": "true"},
            )
            deleted += 1
        except urllib.error.HTTPError as exc:
            print(
                f"::warning::could not delete analysis {analysis['id']} "
                f"(HTTP {exc.code}). Delete it by hand, or the insecure fixtures' "
                f"findings stay in this repo's Code Scanning alerts."
            )
            return 0

    print(f"Deleted {deleted} probe analysis/analyses.")
    return 0


if __name__ == "__main__":
    # Read with .get() above so the pure helpers import without them (the
    # tests do); a run still refuses to start with any of them missing.
    missing = [
        name
        for name, value in (
            ("GITHUB_TOKEN", TOKEN),
            ("GITHUB_REPOSITORY", REPO),
            ("GITHUB_REF", REF),
            ("GITHUB_SHA", SHA),
        )
        if not value
    ]
    if missing:
        print(f"missing environment: {', '.join(missing)}", file=sys.stderr)
        sys.exit(2)
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "verify":
        expect = None
        if "--expect-path" in sys.argv:
            expect = sys.argv[sys.argv.index("--expect-path") + 1]
        report = None
        if "--report-suppressed" in sys.argv:
            report = sys.argv[sys.argv.index("--report-suppressed") + 1]
        sys.exit(verify(expect, report))
    if mode == "cleanup":
        sys.exit(cleanup())
    print(f"usage: {sys.argv[0]} verify|cleanup", file=sys.stderr)
    sys.exit(2)
