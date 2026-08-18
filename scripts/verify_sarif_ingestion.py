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

Usage:
    python scripts/verify_sarif_ingestion.py verify
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

TOKEN = os.environ["GITHUB_TOKEN"]
REPO = os.environ["GITHUB_REPOSITORY"]
REF = os.environ["GITHUB_REF"]
SHA = os.environ["GITHUB_SHA"]


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


def verify() -> int:
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
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "verify":
        sys.exit(verify())
    if mode == "cleanup":
        sys.exit(cleanup())
    print(f"usage: {sys.argv[0]} verify|cleanup", file=sys.stderr)
    sys.exit(2)
