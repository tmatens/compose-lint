#!/usr/bin/env python3
"""Generate `tier_summary.md` for an existing run dir.

Useful when run.py predates the tier_summary writer or when the index has
been re-tiered since the last lint run. Reads results.jsonl + index.jsonl
and writes/overwrites tier_summary.md in the given run dir.

Usage:
  python3 make_tier_summary.py <run_dir>
  python3 make_tier_summary.py latest      # most recent run
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from run import load_index, summarize_tiers  # noqa: E402

RUNS = Path.home() / ".cache" / "compose-lint-corpus" / "runs"


def resolve_run(arg: str) -> Path:
    if arg == "latest":
        runs = sorted((p for p in RUNS.iterdir() if p.is_dir()), key=lambda p: p.name)
        if not runs:
            sys.exit("no runs found")
        return runs[-1]
    p = Path(arg)
    if not p.is_absolute():
        p = RUNS / arg
    if not p.exists():
        sys.exit(f"run dir not found: {p}")
    return p


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.exit(__doc__)
    run_dir = resolve_run(argv[1])
    results_path = run_dir / "results.jsonl"
    if not results_path.exists():
        sys.exit(f"no results.jsonl in {run_dir}")

    results = [json.loads(line) for line in results_path.open()]
    index = load_index()
    summarize_tiers(run_dir, results, index)

    out = run_dir / "tier_summary.md"
    print(f"wrote {out} ({out.stat().st_size} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
