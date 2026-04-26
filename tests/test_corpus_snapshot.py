"""Diff the committed corpus snapshot against the current local run.

Skipped unless `COMPOSE_LINT_CORPUS` points at a corpus cache root
(default layout: `<root>/runs/<timestamp>/results.jsonl` and
`<root>/index.jsonl`). When set, asserts that the snapshot at
`tests/corpus_snapshot.json.gz` matches the latest run's findings —
catches accidental rule-output drift on PRs that touch rule logic.

Refresh the corpus run, then run `python scripts/snapshot.py generate`
and commit the result alongside the rule change.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT_PATH = REPO_ROOT / "tests" / "corpus_snapshot.json.gz"

CORPUS_ENV = os.environ.get("COMPOSE_LINT_CORPUS")

pytestmark = pytest.mark.skipif(not CORPUS_ENV, reason="COMPOSE_LINT_CORPUS not set")


def test_snapshot_matches_latest_run() -> None:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import snapshot as snap

    cache = Path(CORPUS_ENV).expanduser()  # type: ignore[arg-type]
    if not cache.is_dir():
        pytest.skip(f"COMPOSE_LINT_CORPUS path does not exist: {cache}")
    index_path = cache / "index.jsonl"
    if not index_path.is_file():
        pytest.skip(f"no index.jsonl under {cache}")

    run_dir = snap._latest_run_dir(cache)
    expected = snap.read_snapshot(SNAPSHOT_PATH)
    actual = snap.build_digest(run_dir, index_path)
    diff = snap.diff_digests(expected, actual)
    assert not diff, "corpus snapshot drift:\n" + "\n".join(diff)
