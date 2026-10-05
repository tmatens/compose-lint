"""Select a balanced sample of candidates and shallow-clone them.

Selection: per search label up to PER_LABEL repos, repos matching more labels
first; skip forks, archived repos, and anything over MAX_KB. Clones go to
~/.cache/compose-lint-corpus-multi/repos/<owner>__<name> with --depth 1.
Nothing from a clone is executed.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path.home() / ".cache" / "compose-lint-corpus-multi"
REPOS = ROOT / "repos"
PER_LABEL = 50
MAX_KB = 30_000


def meta(full: str) -> dict | None:
    proc = subprocess.run(
        ["gh", "api", f"repos/{full}"], capture_output=True, text=True
    )
    if proc.returncode != 0:
        return None
    d = json.loads(proc.stdout)
    return {
        "size": d["size"],
        "fork": d["fork"],
        "archived": d["archived"],
        "branch": d["default_branch"],
        "sha": None,
    }


def clone(full: str) -> tuple[str, str]:
    dest = REPOS / full.replace("/", "__")
    if dest.exists():
        return full, "exists"
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    proc = subprocess.run(
        [
            "git",
            "clone",
            "-q",
            "--depth",
            "1",
            "--single-branch",
            "--no-tags",
            f"https://github.com/{full}.git",
            str(dest),
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )
    return full, "ok" if proc.returncode == 0 else f"fail:{proc.returncode}"


def main() -> None:
    cands: dict[str, list[str]] = json.loads((ROOT / "candidates.json").read_text())
    rng = random.Random(20261004)
    by_label: dict[str, list[str]] = {}
    for full, labels in cands.items():
        for label in labels:
            by_label.setdefault(label, []).append(full)
    chosen: dict[str, list[str]] = {}
    metas: dict[str, dict] = {}
    for label, repos in sorted(by_label.items()):
        rng.shuffle(repos)
        repos.sort(key=lambda r: -len(cands[r]))
        taken = 0
        for full in repos:
            if taken >= PER_LABEL:
                break
            if full in chosen:
                taken += 1
                continue
            m = metas.get(full) or meta(full)
            if m is None:
                continue
            metas[full] = m
            if m["fork"] or m["archived"] or m["size"] > MAX_KB:
                continue
            chosen[full] = cands[full]
            taken += 1
        print(f"{label}: {taken}", file=sys.stderr)
    REPOS.mkdir(parents=True, exist_ok=True)
    (ROOT / "selection.json").write_text(
        json.dumps(
            {k: {"labels": v, **metas[k]} for k, v in sorted(chosen.items())}, indent=1
        )
    )
    print(f"selected {len(chosen)}", file=sys.stderr)
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(clone, sorted(chosen)))
    ok = sum(1 for _, r in results if r in ("ok", "exists"))
    print(f"cloned {ok}/{len(results)}", file=sys.stderr)
    (ROOT / "clone-results.json").write_text(json.dumps(dict(results), indent=1))


if __name__ == "__main__":
    main()
