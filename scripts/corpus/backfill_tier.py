#!/usr/bin/env python3
"""Backfill `tier` on existing index.jsonl entries.

The original fetch.py predates tiering. Every entry it produced came from
the random gh-search-code method, so it maps cleanly to `tier: longtail`.
This script adds the field in-place, leaving any entry that already has a
tier untouched (so it's safe to rerun after new tiers have been added).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

INDEX = Path.home() / ".cache" / "compose-lint-corpus" / "index.jsonl"
DEFAULT_TIER = "longtail"


def main() -> int:
    if not INDEX.exists():
        print(f"no index at {INDEX}", file=sys.stderr)
        return 0

    tmp = INDEX.with_suffix(".jsonl.tmp")
    backfilled = 0
    kept = 0
    with INDEX.open() as src, tmp.open("w") as dst:
        for line in src:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                dst.write(line)
                continue
            if "tier" not in entry:
                entry["tier"] = DEFAULT_TIER
                backfilled += 1
            else:
                kept += 1
            dst.write(json.dumps(entry) + "\n")
    tmp.replace(INDEX)
    print(f"backfilled {backfilled}; already-tagged {kept}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
