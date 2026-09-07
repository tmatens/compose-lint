#!/usr/bin/env python3
"""Grade the lines a pull request adds or changes, not the repo aggregate.

The `coverage` job in `ci.yml` enforces a repo-wide statement floor, which
is what the OpenSSF Silver `test_statement_coverage80` criterion measures.
A floor cannot see a change that adds untested code: a handful of new
uncovered lines does not move a whole-repo percentage, so the job reads
green either way and "did this change bring tests?" is left to a checkbox
the author ticks about their own work (#802). This runs `diff-cover` over
the `coverage.xml` that job already produced, appends the report to the
step summary, and fails below the patch threshold. The floor is untouched
— this is an additional condition, not a replacement.

It also guards the guard, because the interesting failure here is silence.
`diff-cover` matches a report path against a diff path as text, and when
nothing matches it reports "no lines with coverage information in this
diff" and exits 0. That is the right answer for a docs- or tests-only PR
and the identical answer for a report that has stopped lining up with the
repo — a gate measuring nothing looks exactly like a gate with nothing to
measure, which is the failure this whole check exists to stop one level
down. Two checks separate them:

- Every file `coverage.xml` names must exist here, and it must name some.
  A report written against different paths can never match a diff line.
  This runs on every invocation, not only the quiet ones.
- When nothing was measured, no line the diff adds may be one
  `coverage.xml` calls a statement. This catches a report whose line
  numbers have drifted from the diff's. It is not exhaustive — code
  appended past the report's last statement leaves nothing to intersect —
  so it backs up the path check rather than standing in for it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

# `@@ -old,len +new,len @@` — a one-line hunk omits the `,len`.
_HUNK = re.compile(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@")


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, check=True
    ).stdout


def _fail(message: str) -> int:
    print(f"::error::{message}")
    return 1


def parse_hunk_lines(diff: str) -> set[int]:
    """Post-image line numbers the hunks of a *single-file* diff add.

    One file at a time is what makes this safe. Inside a file's diff every
    content line carries a `+`, `-` or space prefix, so a line starting `@@`
    can only be a hunk header. Across files the header pair is not so lucky:
    a removed line reading `-- x` and an added line reading `++ y` arrive as
    `--- x` and `+++ y`, which is exactly the shape of the `--- a/… +++ b/…`
    pair that separates two files.

    A deletion-only hunk has a zero post-image length and contributes
    nothing, which is right — there is no new line for a test to cover.
    """
    lines: set[int] = set()
    for line in diff.splitlines():
        if match := _HUNK.match(line):
            start = int(match.group(1))
            count = 1 if match.group(2) is None else int(match.group(2))
            lines.update(range(start, start + count))
    return lines


def added_lines(base_sha: str) -> dict[str, set[int]]:
    """Line numbers this diff adds or changes, per file, against `base_sha`.

    `--diff-filter=d` drops deleted files; for a rename the reported path is
    the post-image one, which is the path `coverage.xml` would use.
    """
    listing = _git("diff", "--name-only", "--diff-filter=d", "-z", f"{base_sha}...HEAD")
    added: dict[str, set[int]] = {}
    for path in filter(None, listing.split("\0")):
        numbers = parse_hunk_lines(
            _git("diff", "--unified=0", f"{base_sha}...HEAD", "--", path)
        )
        if numbers:
            added[path] = numbers
    return added


def parse_statement_lines(coverage_xml: Path) -> dict[str, set[int]]:
    """Line numbers `coverage.xml` records as statements, per file.

    Comments, blank lines and `exclude_also` bodies are absent, so a diff
    that only touches those correctly registers as nothing to measure.
    """
    statements: dict[str, set[int]] = {}
    for element in ET.parse(coverage_xml).getroot().iter("class"):
        filename = element.get("filename")
        if filename is None:
            continue
        statements[filename] = {
            int(number)
            for line in element.iter("line")
            if (number := line.get("number")) is not None
        }
    return statements


def missing_paths(statements: dict[str, set[int]], root: Path) -> list[str]:
    """Files `coverage.xml` names that are not files under `root`."""
    return sorted(path for path in statements if not (root / path).is_file())


def unmeasured_statements(
    added: dict[str, set[int]], statements: dict[str, set[int]]
) -> list[str]:
    """`file:line` for every added line `coverage.xml` calls a statement."""
    return sorted(
        f"{path}:{number}"
        for path, numbers in added.items()
        for number in numbers & statements.get(path, set())
    )


def run_diff_cover(
    coverage_xml: Path, base_sha: str, fail_under: float
) -> tuple[int, int]:
    """Run the gate. Returns its exit status and how many lines it measured."""
    with tempfile.TemporaryDirectory() as scratch:
        json_report = Path(scratch) / "patch-coverage.json"
        markdown_report = Path(scratch) / "patch-coverage.md"
        completed = subprocess.run(
            [
                # Invoked as a module, not as the `diff-cover` console
                # script: this runs under whichever interpreter CI installed
                # the dev lockfile into, without depending on its bin
                # directory being on PATH.
                sys.executable,
                "-m",
                "diff_cover.diff_cover_tool",
                str(coverage_xml),
                f"--compare-branch={base_sha}",
                f"--fail-under={fail_under}",
                "--show-uncovered",
                # Comma-separated `--format` replaces the deprecated
                # `--json-report` / `--markdown-report` flags.
                f"--format=json:{json_report},markdown:{markdown_report}",
            ],
            check=False,
        )
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary and markdown_report.exists():
            with open(summary, "a", encoding="utf-8") as handle:
                handle.write(markdown_report.read_text(encoding="utf-8"))
        measured = (
            json.loads(json_report.read_text(encoding="utf-8"))["total_num_lines"]
            if json_report.exists()
            else 0
        )
    return completed.returncode, measured


def main() -> int:
    parser = argparse.ArgumentParser(description="Patch-coverage gate.")
    parser.add_argument("--coverage-xml", type=Path, default=Path("coverage.xml"))
    parser.add_argument("--base-sha", required=True, help="the PR's base commit")
    parser.add_argument("--fail-under", type=float, required=True)
    args = parser.parse_args()

    statements = parse_statement_lines(args.coverage_xml)
    if not statements:
        return _fail(
            f"{args.coverage_xml} names no files. There is nothing for the patch "
            "gate to match a diff against, so it would pass without measuring "
            "anything. Fix the coverage run, not this check."
        )
    if absent := missing_paths(statements, Path.cwd()):
        return _fail(
            f"{args.coverage_xml} names {len(absent)} file(s) that do not exist "
            f"here (e.g. {', '.join(absent[:5])}). Its paths no longer line up "
            "with the repository, so the patch gate would match no diff line and "
            "pass vacuously. Fix the coverage run, not this check."
        )

    status, measured = run_diff_cover(args.coverage_xml, args.base_sha, args.fail_under)
    if status != 0:
        return _fail(
            f"Lines this PR adds or changes are below {args.fail_under:g}% "
            "covered. Add tests for the lines listed above, or mark a genuinely "
            "untestable one `# pragma: no cover` with a comment saying why."
        )
    if measured:
        return 0

    if missed := unmeasured_statements(added_lines(args.base_sha), statements):
        return _fail(
            f"diff-cover measured nothing, but {args.coverage_xml} records "
            f"{len(missed)} statement(s) among the lines this PR adds "
            f"(e.g. {', '.join(missed[:5])}). The gate is passing vacuously on a "
            "report whose line numbers have drifted from the diff. Fix the "
            "coverage run, not this check."
        )

    print("No lines to measure, and coverage.xml agrees. Patch gate satisfied.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
