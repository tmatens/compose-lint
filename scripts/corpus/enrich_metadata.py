#!/usr/bin/env python3
"""Backfill per-repo metadata (stars, pushed_at, default_branch, topics)
into existing index.jsonl entries that are missing these fields.

Resolves the gap between fetcher versions: the original `fetch.py` and
the early `fetch_canonical.py`/`fetch_selfhosted.py` writers stored only
{content_hash, blob_sha, repo, path, url, size, tier}. Without per-repo
metadata in-line, the report can't stratify popular by stars or filter
out abandoned repos by recency without re-fetching everything.

This script:
  1. Loads index.jsonl, groups entries by repo.
  2. For each unique repo missing any metadata field, calls
     `gh api repos/{repo}` (cached + concurrent).
  3. Rewrites index.jsonl with the metadata merged in.

Idempotent: skips repos whose entries already have all fields populated.
404s are tolerated — repo may have been deleted/renamed since fetch;
the entry's tier and other fields stay intact.
"""
from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

INDEX = Path.home() / ".cache" / "compose-lint-corpus" / "index.jsonl"
META_FIELDS = ("stars", "pushed_at", "default_branch", "topics")
WORKERS = 16
GH_API_TIMEOUT = 30


def gh_repo(repo: str) -> dict | None:
    try:
        out = subprocess.run(
            ["gh", "api", "--cache", "24h", f"repos/{repo}"],
            check=True, capture_output=True, text=True, timeout=GH_API_TIMEOUT,
        ).stdout
        return json.loads(out)
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or "").strip()[:160]
        if "Not Found" not in msg and "Moved Permanently" not in msg:
            print(f"  gh api repos/{repo} failed: {msg}", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        return None


def extract(info: dict) -> dict:
    return {
        "stars": info.get("stargazers_count"),
        "pushed_at": info.get("pushed_at"),
        "default_branch": info.get("default_branch"),
        "topics": info.get("topics") or [],
    }


def main() -> int:
    if not INDEX.exists():
        sys.exit(f"no index at {INDEX}")

    entries = [json.loads(line) for line in INDEX.open()]
    print(f"loaded {len(entries)} index entries", file=sys.stderr)

    # Find repos missing any metadata field.
    repos_seen: dict[str, bool] = {}  # repo -> needs_lookup
    for e in entries:
        repo = e["repo"]
        if repo in repos_seen:
            continue
        repos_seen[repo] = any(f not in e for f in META_FIELDS)

    todo = [r for r, needed in repos_seen.items() if needed]
    print(f"unique repos: {len(repos_seen)}; needing lookup: {len(todo)}", file=sys.stderr)

    metadata: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(gh_repo, repo): repo for repo in todo}
        done = 0
        for fut in as_completed(futures):
            repo = futures[fut]
            info = fut.result()
            if info:
                metadata[repo] = extract(info)
            done += 1
            if done % 200 == 0:
                print(f"  fetched {done}/{len(todo)}", file=sys.stderr)

    print(f"got metadata for {len(metadata)}/{len(todo)} repos", file=sys.stderr)

    # Rewrite index with metadata merged in.
    tmp = INDEX.with_suffix(".jsonl.tmp")
    enriched = 0
    with tmp.open("w") as out:
        for e in entries:
            meta = metadata.get(e["repo"])
            if meta:
                for k, v in meta.items():
                    if k not in e and v is not None:
                        e[k] = v
                enriched += 1
            out.write(json.dumps(e) + "\n")
    tmp.replace(INDEX)
    print(f"enriched {enriched} entries", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
