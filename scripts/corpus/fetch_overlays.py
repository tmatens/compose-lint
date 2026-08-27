#!/usr/bin/env python3
"""Fetch Compose *overlay* files (Corpus 2.0, #759 Phase 3).

Overlay/variant files — `docker-compose.override.yml`,
`docker-compose.prod.yml`, `compose.override.yaml`, … — are excluded from
the main corpus by its four-filename allowlist, yet they are where
production port binds and credentials often land, and they exercise the
`include:`/`extends:`/merge coverage-gap machinery. This fetcher gives
them their own stratum.

They land under `tier: overlay` and are **kept out of the blended
prevalence rates** (see `run.EXCLUDED_FROM_PREVALENCE`): an overlay is a
merge *fragment* — linting it standalone is exactly the partial view
compose-lint's coverage-gap exit code exists to warn about — so its
standalone rates are reported as their own lane, not blended with full
files. How often an overlay even parses standalone is itself a finding.

Deliberately slow: the code-search API allows ~10 requests/min, and the
corpus design says there is no rush — QUERY_SLEEP (default 8s) between
searches keeps this fetcher a polite background task.

Same dedup contract as fetch.py: `(repo, path, sha)` at search time,
content hash at download time, blob_sha against the existing index.

Usage:  python3 scripts/corpus/fetch_overlays.py
        QUERY_SLEEP=12 python3 scripts/corpus/fetch_overlays.py
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from fetch import (  # noqa: E402
    FILES,
    INDEX,
    download,
    load_existing,
)

# Variant basenames, most-common first. `test` variants are deliberately
# absent — they are synthetic-path territory, not deployment overlays.
STEMS = ["docker-compose", "compose"]
VARIANTS = ["override", "prod", "production", "dev", "development", "staging", "local"]
EXTS = ["yml", "yaml"]
FILENAMES = [f"{s}.{v}.{e}" for s in STEMS for v in VARIANTS for e in EXTS]

# Two anchors are enough: an overlay that contains neither `services:`
# nor `ports:` is rare, and every extra anchor doubles the query count.
ANCHORS = ["services:", "ports:"]

PER_QUERY_LIMIT = 200
QUERY_SLEEP = float(os.environ.get("QUERY_SLEEP", "8"))
RATE_LIMIT_SLEEP = 70
DOWNLOAD_WORKERS = 8
GLOBAL_TIMEOUT_SECS = int(os.environ.get("FETCH_TIMEOUT", "5400"))


def gh_search(anchor: str, filename: str, retry: bool = True) -> list[dict]:
    cmd = [
        "gh", "search", "code", anchor,
        "--filename", filename,
        "--limit", str(PER_QUERY_LIMIT),
        "--json", "repository,path,sha,url",
    ]
    try:
        out = subprocess.run(
            cmd, check=True, capture_output=True, text=True, timeout=120
        ).stdout
        return json.loads(out)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr or ""
        if "rate limit exceeded" in stderr and retry:
            print(f"  rate-limited; sleeping {RATE_LIMIT_SLEEP}s", file=sys.stderr)
            time.sleep(RATE_LIMIT_SLEEP)
            return gh_search(anchor, filename, retry=False)
        print(f"  search failed ({anchor!r} {filename}): {stderr.strip()[:160]}",
              file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print(f"  search timed out ({anchor!r} {filename})", file=sys.stderr)
        return []


def main() -> int:
    FILES.mkdir(parents=True, exist_ok=True)
    seen = load_existing()
    start = time.monotonic()

    candidates: dict[tuple[str, str, str], dict] = {}
    queries = [(a, fn) for fn in FILENAMES for a in ANCHORS]
    for qi, (anchor, fn) in enumerate(queries):
        if time.monotonic() - start > GLOBAL_TIMEOUT_SECS:
            print("global timeout reached during search", file=sys.stderr)
            break
        print(f"[{qi + 1}/{len(queries)}] search anchor={anchor!r} filename={fn}",
              file=sys.stderr)
        hits = gh_search(anchor, fn)
        added = 0
        for h in hits:
            if Path(h["path"]).name not in FILENAMES:
                continue
            key = (h["repository"]["nameWithOwner"], h["path"], h["sha"])
            if key not in candidates:
                added += 1
            candidates[key] = h
        print(f"   +{added} new (total {len(candidates)})", file=sys.stderr)
        time.sleep(QUERY_SLEEP)

    print(f"unique candidates: {len(candidates)}", file=sys.stderr)

    blob_seen: set[str] = set()
    if INDEX.exists():
        with INDEX.open() as f:
            for line in f:
                try:
                    blob_seen.add(json.loads(line)["blob_sha"])
                except (json.JSONDecodeError, KeyError):
                    continue

    todo = [v for k, v in candidates.items() if k[2] not in blob_seen]
    print(f"new to download: {len(todo)}", file=sys.stderr)

    new_count = 0
    skipped = {"too_large": 0, "http_404": 0, "http_403": 0, "http_429": 0,
               "other": 0, "duplicate": 0}
    with (INDEX.open("a") as idx,
          ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as pool):
        futures = {pool.submit(download, item): item for item in todo}
        for fut in as_completed(futures):
            if time.monotonic() - start > GLOBAL_TIMEOUT_SECS:
                print("global timeout reached during download", file=sys.stderr)
                for f in futures:
                    f.cancel()
                break
            item, data, err = fut.result()
            if err:
                key = err if err in skipped else "other"
                skipped[key] = skipped.get(key, 0) + 1
                continue
            assert data is not None
            content_hash = hashlib.sha256(data).hexdigest()
            if content_hash in seen:
                skipped["duplicate"] += 1
                continue
            seen.add(content_hash)
            (FILES / f"{content_hash}.yml").write_bytes(data)
            idx.write(json.dumps({
                "content_hash": content_hash,
                "blob_sha": item["sha"],
                "repo": item["repository"]["nameWithOwner"],
                "path": item["path"],
                "url": item["url"],
                "size": len(data),
                "tier": "overlay",
            }) + "\n")
            new_count += 1
            if new_count % 100 == 0:
                print(f"  downloaded {new_count}", file=sys.stderr)

    print(f"\nfetched {new_count} new files; corpus now {len(seen)}; "
          f"skipped {skipped}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
