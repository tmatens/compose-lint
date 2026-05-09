"""Shared helpers for the per-tier corpus fetchers.

Each fetch_<tier>.py is responsible for producing a stream of "candidate"
dicts shaped like a `gh search code` hit:

    {"repository": {"nameWithOwner": "..."}, "path": "...", "sha": "<blob>", "url": "<blob_url>"}

…and then calls `download_and_index(candidates, tier=...)` to dedupe,
download, hash, and append to the shared `index.jsonl`.

The `tier` field is appended to every new index entry so reports can
slice rule-prevalence per tier without re-deriving provenance.
"""
from __future__ import annotations

import hashlib
import json
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable

CACHE = Path.home() / ".cache" / "compose-lint-corpus"
FILES = CACHE / "files"
INDEX = CACHE / "index.jsonl"

COMPOSE_FILENAMES = {
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
}

PER_FILE_TIMEOUT = 20
MAX_FILE_BYTES = 256 * 1024
DOWNLOAD_WORKERS = 16


def load_seen_hashes() -> set[str]:
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


def load_seen_blobs() -> set[str]:
    if not INDEX.exists():
        return set()
    seen: set[str] = set()
    with INDEX.open() as f:
        for line in f:
            try:
                seen.add(json.loads(line)["blob_sha"])
            except Exception:
                continue
    return seen


def raw_url(blob_url: str) -> str:
    return (
        blob_url.replace("https://github.com/", "https://raw.githubusercontent.com/", 1)
        .replace("/blob/", "/", 1)
    )


def _download(item: dict) -> tuple[dict, bytes | None, str | None]:
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


def download_and_index(
    candidates: Iterable[dict],
    *,
    tier: str,
    on_progress: int = 100,
) -> dict[str, int]:
    """Download `candidates` in parallel, write new files, append index entries.

    Skips candidates whose blob_sha or content_hash is already indexed.
    Returns a counter dict of {new, duplicate, too_large, http_*, ...}.

    Optional metadata fields on each candidate are copied through to the
    index entry when present (so fetchers that already know them — e.g.
    fetch_popular has stars/pushed_at from `gh search repos` — don't
    have to re-fetch later):

      - ``stars``           — int
      - ``pushed_at``       — ISO-8601 string
      - ``default_branch``  — str
      - ``topics``          — list[str]
    """
    FILES.mkdir(parents=True, exist_ok=True)
    seen_hashes = load_seen_hashes()
    seen_blobs = load_seen_blobs()

    todo = [c for c in candidates if c["sha"] not in seen_blobs]
    print(f"[{tier}] new to download: {len(todo)}", file=sys.stderr)

    counts: dict[str, int] = {"new": 0, "duplicate": 0}
    with INDEX.open("a") as idx, ThreadPoolExecutor(max_workers=DOWNLOAD_WORKERS) as pool:
        futures = {pool.submit(_download, item): item for item in todo}
        for fut in as_completed(futures):
            item, data, err = fut.result()
            if err:
                counts[err] = counts.get(err, 0) + 1
                continue
            assert data is not None
            content_hash = hashlib.sha256(data).hexdigest()
            if content_hash in seen_hashes:
                counts["duplicate"] += 1
                continue
            seen_hashes.add(content_hash)
            (FILES / f"{content_hash}.yml").write_bytes(data)
            entry = {
                "content_hash": content_hash,
                "blob_sha": item["sha"],
                "repo": item["repository"]["nameWithOwner"],
                "path": item["path"],
                "url": item["url"],
                "size": len(data),
                "tier": tier,
            }
            for k in ("stars", "pushed_at", "default_branch", "topics"):
                if k in item:
                    entry[k] = item[k]
            idx.write(json.dumps(entry) + "\n")
            counts["new"] += 1
            if counts["new"] % on_progress == 0:
                print(f"[{tier}]   downloaded {counts['new']}", file=sys.stderr)

    print(f"[{tier}] done: {counts}", file=sys.stderr)
    return counts
