#!/usr/bin/env python3
"""Parallel corpus fix-gate — the multi-core form of tests/test_corpus_fix.py.

Runs the three ADR-014 fix-safety invariants over every corpus file, fanned
across all cores so a full sweep takes ~1-2 min instead of the ~8 min the
single-process pytest gate needs. The pytest gate (`COMPOSE_LINT_CORPUS=… pytest
tests/test_corpus_fix.py`) stays the authoritative, committed check; this is the
fast local loop to run while iterating on a fixer.

For every lintable file it asserts the patched text:
  1. re-parses,
  2. is idempotent (a second collect_edits is a no-op), and
  3. introduces no new finding.

It also reports per-rule "findings fixed" counts — a quick coverage signal to
compare against the baseline in memory after changing a fixer.

    python scripts/corpus/fix_gate.py            # all cores, default corpus
    LINT_WORKERS=4 python scripts/corpus/fix_gate.py

Corpus lives outside the repo at ~/.cache/compose-lint-corpus/files/ (see
README.md). Exits non-zero if any invariant fails.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from collections import Counter
from multiprocessing import Pool
from pathlib import Path

from compose_lint.engine import run_rules
from compose_lint.fix import apply_edits, collect_edits
from compose_lint.parser import (
    ComposeError,
    ComposeNotApplicableError,
    load_compose,
)

CACHE = Path.home() / ".cache" / "compose-lint-corpus"
FILES = CACHE / "files"
WORKERS = int(os.environ.get("LINT_WORKERS", str(os.cpu_count() or 4)))

# Candidates are written into the corpus directory itself (they have to be: a
# relative bind source resolves against the file's own directory, so a candidate
# parked elsewhere is a different document). They are unlinked in a finally, but
# a hard kill can leave one behind — so they carry a distinctive prefix and the
# sweep skips it, rather than silently linting its own leftovers next run.
_CANDIDATE_PREFIX = ".fix_gate_candidate_"


def check_file(path: Path) -> dict:
    """Run the three fix-gate invariants on one file; return a result record."""
    result = {
        "fixed": 0,
        "reparse": None,
        "nonidem": None,
        "introduced": None,
        "by_rule": Counter(),
    }
    try:
        data, lines = load_compose(path)
    except (ComposeError, ComposeNotApplicableError, FileNotFoundError):
        return result
    text = path.read_text(encoding="utf-8")
    findings = run_rules(data, lines)
    collected = collect_edits(findings, data, lines, text)
    if not collected.edits:
        return result
    result["fixed"] = 1
    for finding in collected.fixed:
        result["by_rule"][finding.rule_id] += 1
    patched = apply_edits(text, collected.edits)

    # The temp file must sit in the *original's* directory. Relative and "~"
    # bind sources resolve against the compose file's own directory, so a
    # candidate re-parsed from /tmp is a different document than the one that
    # was linted -- "../x" names a different host path at a different depth.
    # Parking it in /tmp reported 69 spurious "introduced new finding" hits,
    # all of them the gate measuring its own relocation.
    with tempfile.NamedTemporaryFile(
        "w",
        prefix=_CANDIDATE_PREFIX,
        suffix=".yml",
        delete=False,
        encoding="utf-8",
        dir=path.parent,
    ) as handle:
        handle.write(patched)
        patched_path = Path(handle.name)
    try:
        try:
            re_data, re_lines = load_compose(patched_path)
        except (ComposeError, ComposeNotApplicableError) as exc:
            result["reparse"] = f"{path.name}: {exc}"
            return result
        re_findings = run_rules(re_data, re_lines)
        if collect_edits(re_findings, re_data, re_lines, patched).edits:
            result["nonidem"] = path.name
        before = {(f.rule_id, f.service, f.message) for f in findings}
        after = {(f.rule_id, f.service, f.message) for f in re_findings}
        new = after - before
        if new:
            result["introduced"] = f"{path.name}: {sorted(new)[:2]}"
    finally:
        patched_path.unlink(missing_ok=True)
    return result


def main() -> int:
    files = sorted(
        p for p in FILES.glob("*.yml") if not p.name.startswith(_CANDIDATE_PREFIX)
    )
    if not files:
        print(f"no corpus files under {FILES}", file=sys.stderr)
        return 2
    print(f"corpus files: {len(files)} · workers: {WORKERS}", file=sys.stderr)

    reparse: list[str] = []
    nonidem: list[str] = []
    introduced: list[str] = []
    fixed = 0
    by_rule: Counter = Counter()

    started = time.monotonic()
    with Pool(processes=WORKERS) as pool:
        for record in pool.imap_unordered(check_file, files, chunksize=16):
            fixed += record["fixed"]
            by_rule.update(record["by_rule"])
            if record["reparse"]:
                reparse.append(record["reparse"])
            if record["nonidem"]:
                nonidem.append(record["nonidem"])
            if record["introduced"]:
                introduced.append(record["introduced"])
    elapsed = time.monotonic() - started

    print(f"fixed files: {fixed}  ({elapsed:.0f}s)")
    print("findings fixed by rule:")
    for rule_id in sorted(by_rule):
        print(f"  {rule_id}: {by_rule[rule_id]}")
    for label, items in (
        ("reparse failures", reparse),
        ("non-idempotent", nonidem),
        ("introduced new finding", introduced),
    ):
        print(f"{label}: {len(items)}")
        for item in items[:10]:
            print(f"  {item}")

    if reparse or nonidem or introduced:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
