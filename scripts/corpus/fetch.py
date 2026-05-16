#!/usr/bin/env python3
"""Fetch real-world Docker Compose files from GitHub via `gh search code`.

Writes deduped file content into ~/.cache/compose-lint-corpus/files/<sha256>.yml
and an index line per file into ~/.cache/compose-lint-corpus/index.jsonl.

Idempotent: re-running adds new unique files without re-downloading.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

CACHE = Path.home() / ".cache" / "compose-lint-corpus"
FILES = CACHE / "files"
INDEX = CACHE / "index.jsonl"

# Query buckets: vary filename, anchor term, and size range to bypass
# GitHub's ~1000-results-per-query soft cap and pull a more diverse corpus.
FILENAMES = ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]
ANCHORS = ["services:", "image:", "volumes:", "restart:", "ports:", "depends_on:"]
SIZE_BUCKETS = ["<2", "2..5", "5..15", "15..50", ">50"]  # kilobytes

PER_QUERY_LIMIT = 200            # gh search code page cap is ~1000; 200 keeps each call fast
RATE_LIMIT_SLEEP = 70            # GH code search is 30 req/min; back off past one window
PER_FILE_TIMEOUT = 20            # seconds for raw download
MAX_FILE_BYTES = 256 * 1024      # skip giant files (>256 KB) — almost certainly not a real compose
DOWNLOAD_WORKERS = 16
GLOBAL_TIMEOUT_SECS = int(os.environ.get("FETCH_TIMEOUT", "1500"))  # 25 min default


def load_existing() -> set[str]:
    if not INDEX.exists():
        return set()
    seen: set[str] = set()
    with INDEX.open() as f:
        for line in f:
            try:
                seen.add(json.loads(line)["content_hash"])
            except Exception:
                continue
    return seen


def gh_search(anchor: str, filename: str, size: str | None, retry: bool = True) -> list[dict]:
    cmd = [
        "gh", "search", "code", anchor,
        "--filename", filename,
        "--limit", str(PER_QUERY_LIMIT),
        "--json", "repository,path,sha,url",
    ]
    if size:
        cmd += ["--size", size]
    try:
        out = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=120).stdout
        return json.loads(out)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr or ""
        if "rate limit exceeded" in stderr and retry:
            print(f"  rate-limited; sleeping {RATE_LIMIT_SLEEP}s", file=sys.stderr)
            time.sleep(RATE_LIMIT_SLEEP)
            return gh_search(anchor, filename, size, retry=False)
        print(f"  search failed ({anchor!r} {filename} size={size}): {stderr.strip()[:160]}", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print(f"  search timed out ({anchor!r} {filename} size={size})", file=sys.stderr)
        return []


def raw_url(blob_url: str) -> str:
    # https://github.com/OWNER/REPO/blob/SHA/PATH -> https://raw.githubusercontent.com/OWNER/REPO/SHA/PATH
    return blob_url.replace("https://github.com/", "https://raw.githubusercontent.com/", 1).replace("/blob/", "/", 1)


def download(item: dict) -> tuple[dict, bytes | None, str | None]:
    url = raw_url(item["url"])
    req = urllib.request.Request(url, headers={"User-Agent": "compose-lint-corpus/1"})
    try:
        with urllib.request.urlopen(req, timeout=PER_FILE_TIMEOUT) as r:
            data = r.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            return item, None, "too_large"
        return item, data, None
    except urllib.error.HTTPError as e:
        return item, None, f"http_{e.code}"
    except Exception as e:
        return item, None, type(e).__name__


def main() -> int:
    FILES.mkdir(parents=True, exist_ok=True)
    seen = load_existing()
    start = time.monotonic()

    # 1. Collect search hits across (anchor × filename × size) combos.
    #    Stop early if too many recent queries returned only known repos.
    candidates: dict[tuple[str, str, str], dict] = {}
    queries = [(a, fn, sz) for a in ANCHORS for fn in FILENAMES for sz in SIZE_BUCKETS]
    # interleave so a rate-limit pause isn't all on one filename
    for qi, (anchor, fn, size) in enumerate(queries):
        if time.monotonic() - start > GLOBAL_TIMEOUT_SECS:
            print("global timeout reached during search", file=sys.stderr)
            break
        print(f"[{qi+1}/{len(queries)}] search anchor={anchor!r} filename={fn} size={size}", file=sys.stderr)
        hits = gh_search(anchor, fn, size)
        added = 0
        for h in hits:
            if Path(h["path"]).name not in FILENAMES:
                continue
            key = (h["repository"]["nameWithOwner"], h["path"], h["sha"])
            if key not in candidates:
                added += 1
            candidates[key] = h
        print(f"   +{added} new (total {len(candidates)})", file=sys.stderr)

    print(f"unique candidates: {len(candidates)}", file=sys.stderr)

    # 2. Download in parallel. Skip blob shas already seen via index (file already on disk).
    blob_seen: set[str] = set()
    if INDEX.exists():
        with INDEX.open() as f:
            for line in f:
                try:
                    blob_seen.add(json.loads(line)["blob_sha"])
                except (json.JSONDecodeError, KeyError):
                    # Skip a truncated or malformed index line (e.g. a
                    # partial final record from an interrupted append);
                    # it just won't dedupe that blob.
                    continue

    todo = [v for k, v in candidates.items() if k[2] not in blob_seen]
    print(f"new to download: {len(todo)}", file=sys.stderr)

    new_count = 0
    skipped = {"too_large": 0, "http_404": 0, "http_403": 0, "http_429": 0, "other": 0, "duplicate": 0}
    with INDEX.open("a") as idx, ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as pool:
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
                "tier": "longtail",
            }) + "\n")
            new_count += 1
            if new_count % 100 == 0:
                print(f"  downloaded {new_count}", file=sys.stderr)

    print(f"\nfetched {new_count} new files; corpus now {len(seen)}; skipped {skipped}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
