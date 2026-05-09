#!/usr/bin/env python3
"""Fetch Compose files from self-hosted app-store / template registries.

Tier purpose: distinct threat model from `popular`. The popular tier is
"production-adjacent code on the open internet"; self-hosted is "what a
home-lab user installs from a one-click template store on a LAN-exposed
Pi or NAS." Same parser, different deployment context — defaults that
ship in app-store templates are what end up running behind a Tailscale
tunnel or, more often, a port-forward.

Mechanism: hand-curated registry list (CasaOS AppStore, runtipi
appstore, Cosmos AppStore, awesome-compose-style template aggregators).
Each registry follows a `<root>/<app>/docker-compose.yml` convention, so
a single tree walk + filename filter is sufficient — same pattern as
fetch_canonical.py.

Note on dedup: the shared downloader keys on blob_sha + content_hash.
A compose file already pulled by canonical or popular keeps its first-
claimed tier (this script can't reattribute it). For now that's the
chosen tradeoff — the goal is to add new files, not relabel existing ones.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import COMPOSE_FILENAMES, download_and_index  # noqa: E402

TIER = "selfhosted"

# Curated registries — all known to publish compose files under a stable
# `<root>/<app>/(docker-)compose.y(a)ml` layout. Picked for "this is what
# a non-expert installs by clicking 'install' in a self-host UI."
CURATED_REPOS = [
    # CasaOS — large, actively-maintained app store; one compose per app
    "IceWhaleTech/CasaOS-AppStore",
    # runtipi — similar one-click home-server platform
    "runtipi/runtipi-appstore",
    # Cosmos — reverse-proxy + app launcher; ships a curated app library
    "azukaar/Cosmos-Server",
    # Yacht — Portainer alternative; templates live here
    "SelfhostedPro/selfhosted_templates",
    # DockSTARTer — opinionated home-server installer with per-app composes
    "GhostWriters/DockSTARTer",
    # Dockge — compose stack manager with example stacks
    "louislam/dockge",
    # Awesome-compose-style aggregators specifically for self-hosting
    "Haxxnet/Compose-Examples",
    # Self-hosted-friendly mediastack-style bundles
    "geerlingguy/internet-pi",
]


def gh_api(path: str) -> dict | list | None:
    try:
        out = subprocess.run(
            ["gh", "api", "--cache", "1h", path],
            check=True, capture_output=True, text=True, timeout=120,
        ).stdout
        return json.loads(out)
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or "").strip()[:200]
        if "Not Found" not in msg:
            print(f"  gh api failed for {path}: {msg}", file=sys.stderr)
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
    tree = gh_api(f"repos/{repo}/git/trees/{branch}?recursive=1")
    if not isinstance(tree, dict):
        return []
    if tree.get("truncated"):
        # Some app stores have thousands of entries; if the tree is
        # truncated we'll miss tail entries. Worth knowing.
        print(f"  warn: {repo} tree truncated — some files will be missed", file=sys.stderr)
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
        print(f"[selfhosted] {repo}", file=sys.stderr)
        candidates.extend(candidates_for_repo(repo))
    print(f"[selfhosted] candidates: {len(candidates)}", file=sys.stderr)
    download_and_index(candidates, tier=TIER)
    return 0


if __name__ == "__main__":
    sys.exit(main())
