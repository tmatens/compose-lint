"""Collect candidate multi-file Compose repos via GitHub code search.

Read-only. Uses `gh api` (token stays in gh's keyring). Writes candidates.json
into the corpus cache root, beside the clones; nothing from a search lands in git.
Respects the code-search limit (10/min) by sleeping between requests.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

ROOT = Path.home() / ".cache" / "compose-lint-corpus-multi"
OUT = ROOT / "candidates.json"

QUERIES = {
    "include-compose-yaml": '"include:" filename:compose.yaml',
    "include-docker-compose": '"include:" filename:docker-compose.yml',
    "compose-file-env": "COMPOSE_FILE filename:.env",
    "extends-file": '"extends:" "file:" filename:docker-compose.yml',
    "env-file": "env_file filename:docker-compose.yml",
    "override-yml": "filename:docker-compose.override.yml",
    "override-yaml": "filename:compose.override.yaml",
    "project-directory": "project_directory filename:compose.yaml",
}
PAGES = 3


def gh(path: str) -> dict:
    proc = subprocess.run(
        ["gh", "api", "-H", "Accept: application/vnd.github+json", path],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return {"error": proc.stderr.strip()[:200]}
    return json.loads(proc.stdout)


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    found: dict[str, set[str]] = {}
    for label, query in QUERIES.items():
        for page in range(1, PAGES + 1):
            q = urllib.parse.quote(query)
            data = gh(f"search/code?q={q}&per_page=100&page={page}")
            time.sleep(7)  # 10 code-search requests per minute
            if "error" in data:
                print(f"{label} p{page}: {data['error']}", file=sys.stderr)
                break
            items = data.get("items", [])
            for item in items:
                found.setdefault(item["repository"]["full_name"], set()).add(label)
            print(
                f"{label} p{page}: {len(items)} items, {len(found)} repos",
                file=sys.stderr,
            )
            if len(items) < 100:
                break
    OUT.write_text(
        json.dumps({k: sorted(v) for k, v in sorted(found.items())}, indent=1)
    )
    print(f"{len(found)} candidate repos", file=sys.stderr)


if __name__ == "__main__":
    main()
