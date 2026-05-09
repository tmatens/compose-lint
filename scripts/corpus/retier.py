#!/usr/bin/env python3
"""Reattribute index entries to the correct tier by curated-list priority.

The fetchers dedupe on blob_sha (first-write-wins), so a compose file
that exists in both a curated registry and a high-star repo may keep
whichever tier's fetch ran first. That's wrong for analysis: we want
canonical/selfhosted entries to stay tagged as such even when popular
swept them up earlier.

Priority (highest wins):
    canonical > selfhosted > popular > longtail

This script imports the curated `CURATED_REPOS` lists from the
canonical and self-hosted fetchers and re-tags any entry whose `repo`
appears in those lists. Popular and longtail tiers are left alone —
they're the residual buckets, not curated lists.

Idempotent: rerunning produces no changes.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import fetch_canonical  # noqa: E402
import fetch_selfhosted  # noqa: E402

INDEX = Path.home() / ".cache" / "compose-lint-corpus" / "index.jsonl"

# Higher number = higher priority. Used to gate downgrades.
PRIORITY = {"canonical": 4, "selfhosted": 3, "popular": 2, "longtail": 1, "unknown": 0}


def main() -> int:
    if not INDEX.exists():
        sys.exit(f"no index at {INDEX}")

    canonical_repos = set(fetch_canonical.CURATED_REPOS)
    selfhosted_repos = set(fetch_selfhosted.CURATED_REPOS)

    # Sanity: a repo shouldn't be in both lists. If it is, canonical wins
    # (canonical is the upstream-truth tier; selfhosted is one rung down).
    overlap = canonical_repos & selfhosted_repos
    if overlap:
        print(f"warn: repos in both curated lists, canonical wins: {sorted(overlap)}", file=sys.stderr)

    entries = [json.loads(line) for line in INDEX.open()]

    desired_for: dict[str, str] = {}
    for repo in selfhosted_repos:
        desired_for[repo] = "selfhosted"
    for repo in canonical_repos:  # overwrites selfhosted entries on overlap
        desired_for[repo] = "canonical"

    changed = 0
    by_change: dict[tuple[str, str], int] = {}
    for e in entries:
        desired = desired_for.get(e["repo"])
        if not desired:
            continue
        current = e.get("tier", "unknown")
        if current == desired:
            continue
        # Only promote, never demote (so a future curated list shrink
        # doesn't reset a deliberate canonical tag back to popular).
        if PRIORITY[desired] <= PRIORITY[current]:
            continue
        e["tier"] = desired
        changed += 1
        by_change[(current, desired)] = by_change.get((current, desired), 0) + 1

    if changed == 0:
        print("no changes — index already correctly tiered", file=sys.stderr)
        return 0

    tmp = INDEX.with_suffix(".jsonl.tmp")
    with tmp.open("w") as out:
        for e in entries:
            out.write(json.dumps(e) + "\n")
    tmp.replace(INDEX)

    print(f"retiered {changed} entries:", file=sys.stderr)
    for (frm, to), n in sorted(by_change.items()):
        print(f"  {frm:>10s}  ->  {to:<10s}  {n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
