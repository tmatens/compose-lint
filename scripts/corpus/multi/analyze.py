#!/usr/bin/env python3
"""Summarise a multi-file corpus run: agreement with Compose, and a diff of two builds.

Reads the ``results.jsonl`` that ``run.py`` wrote. With one build it reports
where compose-lint and Compose disagree and why; with ``--base`` and
``--head`` it also reports every project whose exit class or rule set moved
between the two builds, which is the before/after evidence a containment or
resolution change needs (ADR-036, ADR-038).

Prints counts, project keys and reason classes only, never file content.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path.home() / ".cache" / "compose-lint-corpus-multi"

# Why an exit 2 happened, from the message. Order matters: the first match wins.
REASONS = (
    (r"opens more than", "cap: files"),
    (r"deeper than", "cap: depth"),
    (r"remote resource", "remote include"),
    (r"interpolated", "interpolated path"),
    (r"was not found", "target missing"),
    (r"outside the repository|outside the project directory", "outside the repository"),
    (r"through a symlink", "link out of reach"),
    (r"declares no service", "base lacks the service"),
    (r"not a Compose document", "target unreadable as Compose"),
    (r"Not a lintable target", "include-only root, nothing readable"),
    (r"not read because", "project .env unreadable"),
    (r"COMPOSE_FILE names", "COMPOSE_FILE refused"),
    (r"cycle|returns to", "cycle"),
    (r"Invalid YAML|Not a valid Compose|not valid", "parse"),
    (r"no 'service:'", "extends without service"),
)


def verdict(entry: dict) -> str:
    rc = entry.get("rc")
    if rc == "timeout":
        return "timeout"
    if entry.get("unparsed"):
        return f"rc{rc}-unparsed"
    if rc == 2:
        return "2[" + (",".join(entry.get("errors", [])) or "none") + "]"
    return str(rc)


def reason(message: str) -> str:
    for pattern, label in REASONS:
        if re.search(pattern, message):
            return label
    return "other"


def rule_counts(entry: dict) -> Counter[str]:
    return Counter(pair.split(":")[0] for pair in entry.get("rules", []))


def report_build(rows: list[dict], name: str) -> None:
    accepted = [r for r in rows if r.get("compose_rc") == 0]
    exit2 = [r for r in accepted if r[name].get("rc") == 2]
    print(f"\n== {name}")
    print("  exit classes:", dict(Counter(verdict(r[name]) for r in rows if name in r)))
    print(f"  Compose accepts, {name} exits 2: {len(exit2)} of {len(accepted)}")
    reasons: Counter[str] = Counter()
    for r in exit2:
        for label in {reason(m) for m in r[name].get("messages", [])} or {
            "(no message)"
        }:
            reasons[label] += 1
    for label, n in reasons.most_common():
        print(f"    {n:5d}  {label}")
    refused = [r for r in rows if r.get("compose_rc") not in (0, "timeout", None)]
    graded = [r for r in refused if r[name].get("rc") in (0, 1)]
    print(
        f"  Compose refuses, {name} grades (0/1): {len(graded)} "
        "(by design, see ADR-036)"
    )


def report_diff(rows: list[dict], base: str, head: str, show: int) -> None:
    both = [r for r in rows if base in r and head in r]
    accepted = [r for r in both if r.get("compose_rc") == 0]
    print(f"\n== {base} -> {head}")
    moved = Counter(
        (verdict(r[base]), verdict(r[head]))
        for r in both
        if verdict(r[base]) != verdict(r[head])
    )
    print(f"  exit class moved: {sum(moved.values())}")
    for (a, b), n in moved.most_common():
        print(f"    {n:5d}  {a} -> {b}")
    regressed = [
        r for r in accepted if r[base].get("rc") in (0, 1) and r[head].get("rc") == 2
    ]
    print(
        f"  REGRESSIONS (Compose accepts, {base} graded, {head} exits 2): "
        f"{len(regressed)}"
    )
    for r in regressed[:show]:
        print("    ", r["project"], "::", "; ".join(r[head].get("messages", []))[:160])
    newly = [
        r for r in accepted if r[base].get("rc") == 2 and r[head].get("rc") in (0, 1)
    ]
    print(
        f"  newly graded: {len(newly)}",
        dict(Counter(r[head]["rc"] for r in newly)),
    )
    graded_by_both = [
        r for r in both if r[base].get("rc") in (0, 1) and r[head].get("rc") in (0, 1)
    ]
    changed = [
        r for r in graded_by_both if r[base].get("rules") != r[head].get("rules")
    ]
    print(f"  graded by both: {len(graded_by_both)}, rule set changed: {len(changed)}")
    for r in changed[:show]:
        a, b = rule_counts(r[base]), rule_counts(r[head])
        print("    ", r["project"], "added", dict(b - a), "removed", dict(a - b))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("results", nargs="?", default=str(ROOT / "results.jsonl"))
    parser.add_argument("--base", help="build name to diff from")
    parser.add_argument("--head", help="build name to diff to")
    parser.add_argument(
        "--show", type=int, default=40, help="projects to list per section"
    )
    args = parser.parse_args()
    if bool(args.base) != bool(args.head):
        parser.error("--base and --head go together")

    with open(args.results, encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle]
    builds = [k for k in rows[0] if k not in ("project", "compose_rc")] if rows else []
    print(f"projects: {len(rows)}")
    print("compose rc:", dict(Counter(str(r.get("compose_rc")) for r in rows)))
    for name in builds:
        report_build(rows, name)
    if args.base:
        report_diff(rows, args.base, args.head, args.show)
    return 0


if __name__ == "__main__":
    sys.exit(main())
