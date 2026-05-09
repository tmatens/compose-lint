#!/usr/bin/env python3
"""Fetch canonical Compose examples from a hand-curated upstream list.

Tier purpose: answer "do the examples people copy-paste ship insecure
defaults?" — high citation value at low N. Files are pulled from official
docker-library example repos, vendor-curated chart repos, and the
docker/awesome-compose reference set.

Mechanism: for each curated repo, list the default-branch tree via
`gh api repos/{repo}/git/trees/HEAD?recursive=1`, filter to compose
filenames, and hand the candidates to the shared downloader.

Idempotent: rerunning is cheap because the shared downloader skips
blob_shas already in the index.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import COMPOSE_FILENAMES, download_and_index  # noqa: E402

TIER = "canonical"

# Curated upstream repos. Picked for "this is what new users copy from a
# README." Each entry is a `owner/name` slug; default branch is resolved
# at runtime so we don't hardcode `main` vs `master`.
CURATED_REPOS = [
    # Vendor reference sets
    "docker/awesome-compose",
    "bitnami/containers",
    "linuxserver/docker-documentation",
    # Docker Hub official-image docs (compose snippets in *.md + examples/)
    "docker-library/docs",
    # Popular self-host platforms whose docs are the canonical install path
    "traefik/traefik",
    "nextcloud/docker",
    "louislam/uptime-kuma",
    "gotify/server",
    "dani-garcia/vaultwarden",
    "jellyfin/jellyfin",
    "grafana/grafana",
    "pi-hole/docker-pi-hole",
    # Official engine examples
    "docker/compose",
]


def gh_api(path: str) -> dict | list | None:
    try:
        out = subprocess.run(
            ["gh", "api", "--cache", "1h", path],
            check=True, capture_output=True, text=True, timeout=120,
        ).stdout
        return json.loads(out)
    except subprocess.CalledProcessError as e:
        print(f"  gh api failed for {path}: {(e.stderr or '').strip()[:200]}", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print(f"  gh api timeout for {path}", file=sys.stderr)
        return None


def default_branch(repo: str) -> str | None:
    info = gh_api(f"repos/{repo}")
    if isinstance(info, dict):
        return info.get("default_branch")
    return None


def list_compose_paths(repo: str, branch: str) -> list[dict]:
    """Return [{path, sha}, ...] for every compose file in the repo tree."""
    tree = gh_api(f"repos/{repo}/git/trees/{branch}?recursive=1")
    if not isinstance(tree, dict):
        return []
    if tree.get("truncated"):
        # Tree exceeded GitHub's response limit; we'll get most files but
        # not all. Acceptable for canonical tier — these repos are small.
        print(f"  warn: {repo} tree truncated", file=sys.stderr)
    out = []
    for entry in tree.get("tree", []):
        if entry.get("type") != "blob":
            continue
        path = entry.get("path", "")
        if Path(path).name in COMPOSE_FILENAMES:
            out.append({"path": path, "sha": entry["sha"]})
    return out


def candidates_for_repo(repo: str) -> list[dict]:
    branch = default_branch(repo)
    if not branch:
        return []
    files = list_compose_paths(repo, branch)
    print(f"  {repo}@{branch}: {len(files)} compose file(s)", file=sys.stderr)
    info = gh_api(f"repos/{repo}") or {}
    base = {
        "stars": info.get("stargazers_count"),
        "pushed_at": info.get("pushed_at"),
        "default_branch": branch,
        "topics": info.get("topics") or [],
    }
    return [
        {
            "repository": {"nameWithOwner": repo},
            "path": f["path"],
            "sha": f["sha"],
            "url": f"https://github.com/{repo}/blob/{branch}/{f['path']}",
            **base,
        }
        for f in files
    ]


def main() -> int:
    candidates: list[dict] = []
    for repo in CURATED_REPOS:
        print(f"[canonical] {repo}", file=sys.stderr)
        candidates.extend(candidates_for_repo(repo))
    print(f"[canonical] candidates: {len(candidates)}", file=sys.stderr)
    download_and_index(candidates, tier=TIER)
    return 0


if __name__ == "__main__":
    sys.exit(main())
