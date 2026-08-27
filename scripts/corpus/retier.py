#!/usr/bin/env python3
"""Reattribute index entries to the correct tier.

Two jobs, applied as one priority scheme:

1. **Curated-list priority** (original job). The fetchers dedupe on
   blob_sha (first-write-wins), so a compose file that exists in both a
   curated registry and a high-star repo may keep whichever tier's fetch
   ran first. We want canonical/selfhosted entries tagged as such even
   when another fetch swept them up earlier. The curated lists are
   imported from the canonical and self-hosted fetchers.

2. **Composition taxonomy** (2026-08-27 corpus analysis). Three kinds of
   entries were measured to distort per-tier prevalence stats and are
   attributed to their own tiers:

   - ``lab`` — deliberately-vulnerable environments (vulhub CVE
     reproductions, CTF challenge archives). Measured: they *dilute*
     rather than inflate (vulhub: 0.7% files-with-CRITICAL, 0% CL-0001,
     8.91 findings/file vs the popular tier's 13.29) — but intent, not
     direction, is the exclusion criterion: a lab target answers no
     tier's threat-model question.
   - ``synthetic`` — test *inputs* to compose tooling: files under
     test/fixture/e2e path segments anywhere, plus whole repos whose
     compose files exist to exercise a tool (docker/compose e2e
     fixtures, podman-compose, kompose). Measured: 97.3% with-findings
     vs 90.6% for plain files — minimal snippets omit every hardening
     key by construction. docker/compose alone was 27% of the canonical
     tier and pulled its with-findings rate from 78.1% to 83.7%.
     Examples/templates/demos are deliberately NOT synthetic: they are
     copy-paste material, which is exactly the population the canonical
     and selfhosted tiers exist to measure.
   - ``collections`` — template/recipe collection repos split out of
     ``popular`` by file count (>= COLLECTION_MIN_FILES corpus entries
     from one repo). Measured: the popular tier was bimodal — collection
     repos averaged 9.02 findings/file with 6.4% CL-0001 while ordinary
     projects' own compose files averaged 19.43 with 15.0% CL-0001. One
     blended tier described neither population.

Priority (highest wins):
    lab > synthetic > canonical > selfhosted > collections > popular > longtail

Entries are only ever promoted, never demoted (so a future curated-list
shrink or threshold change doesn't silently reset a deliberate tag).

Prevalence exclusion for ``lab`` and ``synthetic`` lives in
``run.EXCLUDED_FROM_PREVALENCE`` — this script only attributes.

Idempotent: rerunning produces no changes.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).parent))
import fetch_canonical  # noqa: E402
import fetch_selfhosted  # noqa: E402

INDEX = Path.home() / ".cache" / "compose-lint-corpus" / "index.jsonl"

# Higher number = higher priority. Used to gate downgrades.
PRIORITY = {
    "lab": 7,
    "synthetic": 6,
    "canonical": 5,
    "selfhosted": 4,
    "collections": 3,
    "popular": 2,
    "longtail": 1,
    "unknown": 0,
}

# Deliberately-vulnerable environments: CVE reproduction stacks and CTF
# challenge archives. Curated, not pattern-matched — repo names like
# "TaxHacker" or hackathon projects are ordinary apps and stay put.
LAB_REPOS = {
    "vulhub/vulhub",
    "sajjadium/ctf-archives",
    "cscosu/buckeyectf-2021",
    "UrmiaCTF/UCTF-2024",
    "acisoru/vrnctf-6-kids-writeups",
    "Team-Drovosec/sasctf-quals-2025",
}

# Repos whose compose files exist to exercise a compose tool, wholesale.
# docker/compose was fetched as canonical ("official engine examples")
# until the 2026-08-27 analysis showed every one of its 92 files is a
# pkg/e2e or testdata fixture.
SYNTHETIC_REPOS = {
    "docker/compose",
    "containers/podman-compose",
    "kubernetes/kompose",
}

# A file whose directory path contains one of these segments is a test
# input regardless of repo. Matched on exact lowercased path segments
# (not substrings — "latest/" or "contest/" must not match).
SYNTHETIC_SEGMENTS = {
    "test", "tests", "testing", "testdata", "e2e",
    "fixture", "fixtures", "spec", "specs", "__tests__",
}

# A repo contributing this many corpus entries is a template/recipe
# collection, not a project shipping its own compose file. Counted over
# entries left in popular/collections after lab/synthetic/curated
# attribution, so the threshold is stable across reruns.
COLLECTION_MIN_FILES = 20


def synthetic_path(path: str) -> bool:
    parts = PurePosixPath(path).parts[:-1]  # basename is always compose-named
    return any(seg.lower() in SYNTHETIC_SEGMENTS for seg in parts)


def main() -> int:
    if not INDEX.exists():
        sys.exit(f"no index at {INDEX}")

    canonical_repos = set(fetch_canonical.CURATED_REPOS)
    selfhosted_repos = set(fetch_selfhosted.CURATED_REPOS)

    # Sanity: a repo shouldn't be in both lists. If it is, canonical wins
    # (canonical is the upstream-truth tier; selfhosted is one rung down).
    overlap = canonical_repos & selfhosted_repos
    if overlap:
        print(f"warn: repos in both curated lists, canonical wins: {sorted(overlap)}", file=sys.stderr)

    entries = [json.loads(line) for line in INDEX.open()]

    def desired_base(e: dict) -> str | None:
        if e["repo"] in LAB_REPOS:
            return "lab"
        if e["repo"] in SYNTHETIC_REPOS or synthetic_path(e["path"]):
            return "synthetic"
        if e["repo"] in canonical_repos:
            return "canonical"
        if e["repo"] in selfhosted_repos:
            return "selfhosted"
        return None

    base = {id(e): desired_base(e) for e in entries}

    # Collections threshold: count per-repo over entries that remain
    # popular/collections once lab/synthetic/curated claims are applied.
    residual = Counter(
        e["repo"]
        for e in entries
        if base[id(e)] is None and e.get("tier") in ("popular", "collections")
    )
    collection_repos = {r for r, n in residual.items() if n >= COLLECTION_MIN_FILES}

    changed = 0
    by_change: dict[tuple[str, str], int] = {}
    for e in entries:
        desired = base[id(e)]
        in_residual = e.get("tier") in ("popular", "collections")
        if desired is None and in_residual and e["repo"] in collection_repos:
            desired = "collections"
        if not desired:
            continue
        current = e.get("tier", "unknown")
        if current == desired:
            continue
        # Only promote, never demote (so a future curated list shrink
        # doesn't reset a deliberate tag).
        if PRIORITY[desired] <= PRIORITY[current]:
            continue
        e["tier"] = desired
        changed += 1
        by_change[(current, desired)] = by_change.get((current, desired), 0) + 1

    if changed == 0:
        print("no changes — index already correctly tiered", file=sys.stderr)
        return 0

    tmp = INDEX.with_suffix(".jsonl.tmp")
    with tmp.open("w") as out:
        for e in entries:
            out.write(json.dumps(e) + "\n")
    tmp.replace(INDEX)

    print(f"retiered {changed} entries:", file=sys.stderr)
    for (frm, to), n in sorted(by_change.items()):
        print(f"  {frm:>10s}  ->  {to:<10s}  {n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
