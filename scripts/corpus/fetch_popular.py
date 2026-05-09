#!/usr/bin/env python3
"""Fetch Compose files from popular (highly-starred) GitHub repos.

Tier purpose: answer "what does production-adjacent code look like?" —
production code is private, but high-star public repos are the closest
honest proxy. This is the tier most readers will trust as 'real.'

Mechanism:
  1. `gh search repos` across several topic facets (docker-compose,
     selfhosted, etc.) sorted by stars, with stars>=MIN_STARS and
     pushed within the recency window.
  2. Dedupe by repo slug.
  3. For each repo, walk the default-branch tree and pick out compose files.
  4. Hand candidates to the shared downloader.

Notes:
  - `gh search repos` caps at 1000 results per query, but topic-faceted
    queries rarely hit that ceiling at stars>=50, so we skip date-window
    sharding here (unlike fetch.py).
  - Tree walks are cached for 1h via `gh api --cache 1h`, so reruns are
    fast and friendly to the rate limiter.
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import COMPOSE_FILENAMES, download_and_index  # noqa: E402

TIER = "popular"

# Topic facets — each runs as a separate `gh search repos` query so we
# can pull up to 1000 repos per facet before the API caps us.
TOPICS = [
    "docker-compose",
    "compose",
    "self-hosted",
    "selfhosted",
    "homelab",
    "containers",
]

MIN_STARS = 50
RECENCY_DAYS = 730  # 2 years
PER_TOPIC_LIMIT = 1000  # gh search repos hard cap
MAX_REPOS_PER_TREE_WALK = 2000  # safety: don't blow the API budget on a single run
GH_API_TIMEOUT = 60


def gh_search_repos(topic: str, pushed_after: str) -> list[dict]:
    cmd = [
        "gh", "search", "repos",
        f"topic:{topic}",
        "--sort", "stars",
        "--order", "desc",
        f"--stars=>={MIN_STARS}",
        f"--updated=>={pushed_after}",
        "--limit", str(PER_TOPIC_LIMIT),
        "--json", "fullName,stargazersCount,defaultBranch,pushedAt",
    ]
    try:
        out = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=120).stdout
        return json.loads(out)
    except subprocess.CalledProcessError as e:
        print(f"  search repos failed (topic={topic}): {(e.stderr or '').strip()[:200]}", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print(f"  search repos timeout (topic={topic})", file=sys.stderr)
        return []


def gh_api(path: str) -> dict | list | None:
    try:
        out = subprocess.run(
            ["gh", "api", "--cache", "1h", path],
            check=True, capture_output=True, text=True, timeout=GH_API_TIMEOUT,
        ).stdout
        return json.loads(out)
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or "").strip()[:200]
        # Empty repos or 404s on the tree endpoint are common — log quietly.
        if "Not Found" not in msg:
            print(f"  gh api failed for {path}: {msg}", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        return None


def list_compose_paths(repo: str, branch: str) -> list[dict]:
    tree = gh_api(f"repos/{repo}/git/trees/{branch}?recursive=1")
    if not isinstance(tree, dict):
        return []
    out = []
    for entry in tree.get("tree", []):
        if entry.get("type") != "blob":
            continue
        path = entry.get("path", "")
        if Path(path).name in COMPOSE_FILENAMES:
            out.append({"path": path, "sha": entry["sha"]})
    return out


def collect_repos() -> dict[str, dict]:
    """Run topic searches, dedupe by repo slug, return {fullName: meta}."""
    pushed_after = (date.today() - timedelta(days=RECENCY_DAYS)).isoformat()
    repos: dict[str, dict] = {}
    for topic in TOPICS:
        print(f"[popular] search topic={topic}", file=sys.stderr)
        hits = gh_search_repos(topic, pushed_after)
        added = 0
        for h in hits:
            slug = h["fullName"]
            if slug not in repos:
                repos[slug] = h
                added += 1
        print(f"   +{added} new (total {len(repos)})", file=sys.stderr)
    return repos


def main() -> int:
    repos = collect_repos()
    if len(repos) > MAX_REPOS_PER_TREE_WALK:
        # Sort by stars desc and cap — we'd rather walk the most popular
        # than starve the API budget on the long tail.
        ranked = sorted(repos.values(), key=lambda r: r.get("stargazersCount", 0), reverse=True)
        repos = {r["fullName"]: r for r in ranked[:MAX_REPOS_PER_TREE_WALK]}
        print(f"[popular] capped tree walks at top {MAX_REPOS_PER_TREE_WALK} by stars", file=sys.stderr)

    candidates: list[dict] = []
    for i, (slug, meta) in enumerate(repos.items(), 1):
        branch = meta.get("defaultBranch") or "main"
        files = list_compose_paths(slug, branch)
        if files:
            print(f"[popular] [{i}/{len(repos)}] {slug} ({meta.get('stargazersCount', '?')}★): {len(files)} file(s)", file=sys.stderr)
        for f in files:
            candidates.append({
                "repository": {"nameWithOwner": slug},
                "path": f["path"],
                "sha": f["sha"],
                "url": f"https://github.com/{slug}/blob/{branch}/{f['path']}",
                "stars": meta.get("stargazersCount"),
                "pushed_at": meta.get("pushedAt"),
                "default_branch": branch,
            })

    print(f"[popular] candidates: {len(candidates)}", file=sys.stderr)
    download_and_index(candidates, tier=TIER)
    return 0


if __name__ == "__main__":
    sys.exit(main())
