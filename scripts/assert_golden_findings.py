#!/usr/bin/env python3
"""Compare a surface's report against the golden finding set (#621).

Every cross-surface smoke used to assert one bit: exit 0 versus exit 1.
``tests/smoke/insecure.yml`` trips six rules and only one of them is at or
above the default threshold, so a surface could stop reporting five of the
six and every smoke stayed green. The failure is invisible in exactly the
direction that matters for a security linter — fewer findings, same
verdict.

This is the shared comparator. It reads a compose-lint report in **json or
sarif** and holds it to ``tests/smoke/insecure.golden.json``. Both are
accepted because not every surface can emit both: the GitHub Action writes
SARIF and never JSON, and ``tests/test_format_equivalence.py`` is what
makes reading the SARIF equivalent to reading the JSON (#623).

Two properties make one golden file work everywhere:

* **The reported set does not depend on ``--fail-on``.** The threshold
  moves the exit code, not the findings — verified across low/high/critical.
  So a surface may use whatever threshold it likes.
* **The path is not part of the key.** Docker sees the fixture mounted at
  ``/src/docker-compose.yml``, the Action sees ``tests/smoke/insecure.yml``.
  Each smoke lints exactly one file, which the comparator asserts, so
  ``(rule, line)`` identifies a finding unambiguously.

Usage:
    compose-lint --format json ... | python3 scripts/assert_golden_findings.py
    python3 scripts/assert_golden_findings.py --surface docker report.json
    python3 scripts/assert_golden_findings.py --update < report.json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

REPO = pathlib.Path(__file__).resolve().parent.parent
GOLDEN = REPO / "tests" / "smoke" / "insecure.golden.json"

# The documented severity -> SARIF level correspondence
# (src/compose_lint/formatters/sarif.py, `_SARIF_LEVEL`).
SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _load_report(raw: str) -> tuple[str, list[dict[str, Any]], set[str]]:
    """Normalise json or sarif to ``(kind, findings, files)``."""
    document = json.loads(raw)
    if "runs" in document:
        results = document["runs"][0]["results"]
        findings = []
        files = set()
        for r in results:
            physical = r["locations"][0]["physicalLocation"]
            files.add(physical["artifactLocation"]["uri"])
            findings.append(
                {
                    "rule": r["ruleId"],
                    "line": physical["region"]["startLine"],
                    "level": r["level"],
                    "suppressed": bool(r.get("suppressions")),
                }
            )
        return "sarif", findings, files
    findings = [
        {
            "rule": f["rule_id"],
            "line": f["line"],
            "severity": f["severity"],
            "service": f["service"],
            "suppressed": bool(f["suppressed"]),
        }
        for f in document["findings"]
    ]
    return "json", findings, {f["file"] for f in document["findings"]}


def _key(findings: list[dict[str, Any]]) -> set[tuple[str, int]]:
    return {(f["rule"], f["line"]) for f in findings}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", nargs="?", help="report file (default: stdin)")
    parser.add_argument("--surface", default="report", help="name used in messages")
    parser.add_argument(
        "--in-text",
        action="store_true",
        help=(
            "input is human-readable output, not json/sarif: assert every "
            "golden rule id appears in it (the pre-commit hook's only view)"
        ),
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="rewrite the golden from this report (json only)",
    )
    args = parser.parse_args()

    # Every diagnostic this script prints contains an em dash, and its own
    # error prefix is read by a human. On Windows a piped stdout defaults to
    # cp1252, so `print()` raises UnicodeEncodeError — an *unhandled* one,
    # which exits 1. That is indistinguishable from "the comparison failed",
    # except the reason never reaches anyone: the process reports the right
    # code for the wrong cause and prints nothing. Pin both streams to UTF-8
    # before writing anything.
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

    # UTF-8 explicitly, both ways. Text reports carry the verdict marks and
    # excerpt gutters (⚠ · │ ─), and Windows defaults these to the locale
    # encoding — cp1252 — which mangles or refuses them. The workflows pass a
    # path; stdin stays supported for ad-hoc use.
    if args.report:
        raw = pathlib.Path(args.report).read_text(encoding="utf-8")
    else:
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        raw = sys.stdin.read()

    if args.in_text:
        # The pre-commit hook runs the CLI in text mode and there is no way to
        # ask it for json — `args:` in the manifest is what a consumer
        # overrides, not something a smoke can inject. So this surface gets the
        # assertion it can support: every rule the golden says fires must be
        # named in what the hook actually printed. Weaker than a set
        # comparison, and still far past "it exited 1".
        golden_text = json.loads(GOLDEN.read_text(encoding="utf-8"))["findings"]
        missing = [g["rule"] for g in golden_text if g["rule"] not in raw]
        if missing:
            print(
                f"::error::[{args.surface}] output does not mention "
                f"{sorted(missing)} — the golden set says they fire on this fixture"
            )
            return 1
        print(
            f"[{args.surface}] all {len(golden_text)} golden rule(s) appear in the output"
        )
        return 0

    kind, findings, files = _load_report(raw)

    if args.update:
        if kind != "json":
            print("::error::--update needs a json report (sarif has no severity)")
            return 2
        GOLDEN.write_text(
            json.dumps(
                {
                    "_comment": (
                        "Golden finding set for tests/smoke/insecure.yml, shared by "
                        "every surface smoke (#621). Regenerate with: compose-lint "
                        "check --format json --fail-on low tests/smoke/insecure.yml "
                        "| python3 scripts/assert_golden_findings.py --update"
                    ),
                    "fixture": "tests/smoke/insecure.yml",
                    "findings": sorted(findings, key=lambda f: (f["rule"], f["line"])),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"golden updated: {len(findings)} finding(s)")
        return 0

    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))["findings"]

    if len(files) != 1:
        print(
            f"::error::[{args.surface}] expected exactly one linted file, saw "
            f"{sorted(files)} — (rule, line) is only unambiguous for a single file"
        )
        return 1

    want, got = _key(golden), _key(findings)
    if want != got:
        missing = sorted(want - got)
        extra = sorted(got - want)
        print(f"::error::[{args.surface}] finding set does not match the golden")
        if missing:
            print(f"  missing (golden has, {args.surface} did not report): {missing}")
        if extra:
            print(f"  unexpected ({args.surface} reported, golden does not): {extra}")
        return 1

    by_key = {(f["rule"], f["line"]): f for f in findings}
    for g in golden:
        actual = by_key[(g["rule"], g["line"])]

        # Severity, in whichever vocabulary this format speaks.
        if kind == "json":
            if actual["severity"] != g["severity"]:
                print(
                    f"::error::[{args.surface}] {g['rule']} severity is "
                    f"{actual['severity']!r}, golden says {g['severity']!r}"
                )
                return 1
            if actual["service"] != g["service"]:
                print(
                    f"::error::[{args.surface}] {g['rule']} service is "
                    f"{actual['service']!r}, golden says {g['service']!r}"
                )
                return 1
        elif actual["level"] != SARIF_LEVEL[g["severity"]]:
            print(
                f"::error::[{args.surface}] {g['rule']} SARIF level is "
                f"{actual['level']!r}, expected {SARIF_LEVEL[g['severity']]!r} "
                f"for {g['severity']}"
            )
            return 1

        # Suppression, in both formats. These smokes run with no config, so a
        # suppressed finding means the surface picked one up from somewhere —
        # the Docker mount question (#625) surfacing as a quietly smaller
        # result set rather than as an error.
        if actual["suppressed"] != g["suppressed"]:
            print(
                f"::error::[{args.surface}] {g['rule']} suppressed="
                f"{actual['suppressed']}, golden says {g['suppressed']} — a "
                "surface applying a config the others do not is a divergence"
            )
            return 1

    print(
        f"[{args.surface}] {len(got)} finding(s) match the golden set "
        f"({', '.join(sorted(r for r, _ in got))})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
