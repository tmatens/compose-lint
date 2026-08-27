#!/usr/bin/env python3
"""Backfill `blob_authored_at` on index.jsonl entries (Corpus 2.0, #759).

For each corpus file, records the authored date of the most recent commit
that touched its path on the repo's default branch **at or before the
snapshot date** — i.e. approximately when the captured content was
written. This feeds the report's temporal breakdown ("current practice
vs fossil record"); repo `pushed_at` (enrich_metadata.py) dates the
*repo*, not the file.

Design constraints (deliberate):
- **GraphQL, batched**: one query carries up to BATCH history lookups as
  aliases, so the whole corpus is a few hundred requests against the
  GraphQL points budget instead of ~5.4k REST calls that would drain the
  hourly REST allowance.
- **Slow on purpose**: SLEEP_SECS (default 6) between queries; 60s
  backoff on rate-limit or transport errors. There is no rush; the run
  is resumable, so being polite costs nothing.
- **Resumable / idempotent**: entries that already carry the field are
  skipped; the index is rewritten atomically after every flushed batch,
  so an interrupted run loses at most one batch.
- Missing data is recorded as null, not retried forever: deleted or
  now-private repos, paths absent from the default branch (we fetched
  some files from non-default refs), and empty histories all yield null.

Auth rides on the gh CLI (`gh api graphql`) — no token handling here.

Usage:  python3 scripts/corpus/enrich_blob_dates.py
        SLEEP_SECS=10 BATCH=10 python3 scripts/corpus/enrich_blob_dates.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

INDEX = Path.home() / ".cache" / "compose-lint-corpus" / "index.jsonl"

# Last commit touching the path at or before this instant — the day after
# the snapshot's fetch date, so same-day commits are included.
SNAPSHOT_UNTIL = "2026-08-12T00:00:00Z"

BATCH = int(os.environ.get("BATCH", "20"))
SLEEP_SECS = float(os.environ.get("SLEEP_SECS", "6"))
FIELD = "blob_authored_at"


def gql(query: str) -> dict | None:
    try:
        out = subprocess.run(
            ["gh", "api", "graphql", "-f", f"query={query}"],
            check=True, capture_output=True, text=True, timeout=120,
        ).stdout
        return json.loads(out)
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        # Partial data with errors still lands on stdout as JSON; use it.
        if e.stdout:
            try:
                return json.loads(e.stdout)
            except json.JSONDecodeError:
                pass
        print(f"  query failed: {stderr[:160]}", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print("  query timed out", file=sys.stderr)
        return None


def build_query(items: list[dict]) -> str:
    """One top-level repository alias per entry (r0..rN), one history each.

    Repos repeat across aliases when a batch has several files from one
    repo; that keeps alias bookkeeping trivial and batches are small.
    """
    parts = []
    for i, e in enumerate(items):
        owner, name = e["repo"].split("/", 1)
        parts.append(
            f'r{i}: repository(owner:{json.dumps(owner)}, name:{json.dumps(name)}) {{'
            f' defaultBranchRef {{ target {{ ... on Commit {{'
            f' history(first:1, path:{json.dumps(e["path"])},'
            f' until:{json.dumps(SNAPSHOT_UNTIL)})'
            f' {{ nodes {{ authoredDate }} }} }} }} }} }}'
        )
    return "query { " + " ".join(parts) + " }"


def extract(resp: dict | None, i: int) -> str | None:
    try:
        assert resp is not None
        nodes = resp["data"][f"r{i}"]["defaultBranchRef"]["target"]["history"]["nodes"]
        return nodes[0]["authoredDate"] if nodes else None
    except (AssertionError, KeyError, TypeError, IndexError):
        return None


def flush(entries: list[dict]) -> None:
    tmp = INDEX.with_suffix(".jsonl.tmp")
    with tmp.open("w") as out:
        for e in entries:
            out.write(json.dumps(e) + "\n")
    tmp.replace(INDEX)


def main() -> int:
    if not INDEX.exists():
        sys.exit(f"no index at {INDEX}")
    entries = [json.loads(line) for line in INDEX.open()]
    todo = [e for e in entries if FIELD not in e]
    print(f"{len(entries)} entries, {len(todo)} to enrich "
          f"(batch={BATCH}, sleep={SLEEP_SECS}s)", file=sys.stderr)

    done = 0
    dated = 0
    for start in range(0, len(todo), BATCH):
        batch = todo[start:start + BATCH]
        resp = gql(build_query(batch))
        if resp is None:
            print("  backing off 60s", file=sys.stderr)
            time.sleep(60)
            resp = gql(build_query(batch))
        for i, e in enumerate(batch):
            val = extract(resp, i)
            e[FIELD] = val  # null stays null — recorded, not retried
            if val:
                dated += 1
        done += len(batch)
        flush(entries)
        if done % 200 < BATCH:
            print(f"  {done}/{len(todo)} ({dated} dated)", file=sys.stderr)
        time.sleep(SLEEP_SECS)

    print(f"enriched {done}; dated {dated}, null {done - dated}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
