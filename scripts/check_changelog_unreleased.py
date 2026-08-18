#!/usr/bin/env python3
"""Validate the shape of CHANGELOG.md's ``[Unreleased]`` section.

One definition, two call sites (#593):

- ci.yml's ``changelog-gate`` job runs it on every PR that touches
  CHANGELOG.md, so a duplicate, unknown, or out-of-order section is caught
  on the PR that introduces it — #590 landed ``### Known limitations`` on
  fully green CI and cost the first 0.19.0 release-prep dispatch, because
  this check only existed inside release-prep.yml's heredoc.
- release-prep.yml runs it with ``--require-content`` as the last line of
  defence before the section is renamed into the release. The emptiness
  rule stays dispatch-only: a PR that adds no user-facing entry is
  legitimate, an empty section at release time is not (0.17.0 nearly
  shipped blank notes).

release-prep.yml only *renames* ``[Unreleased]`` -> ``[X.Y.Z]``; it never
authors or reorders entries, so whatever shape the section is in is what
ships — in the GitHub Release notes too.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

# Keep a Changelog's order, with this repo's "Upgrading" preamble first and
# its "Known limitations" postscript last. Both are local conventions that
# predate this check: "Upgrading from 0.15.x"/"0.16.x" already shipped
# inside released sections, and "Known limitations" landed in #590. The
# versioned "Upgrading from X.Y.x" spelling is normalised to the bare key so
# the ordering comparison sees one heading, not an unknown one.
ORDER = [
    "Upgrading",
    "Added",
    "Changed",
    "Deprecated",
    "Removed",
    "Fixed",
    "Security",
    "Known limitations",
]


def _key(heading: str) -> str:
    if re.fullmatch(r"Upgrading(\s+from\s+.+)?", heading):
        return "Upgrading"
    return heading


def validate(text: str, *, require_content: bool) -> str | None:
    """Return an error message, or ``None`` when the section is well-formed."""
    lines = text.splitlines()
    start = next(
        (i for i, ln in enumerate(lines) if ln.startswith("## [Unreleased]")), None
    )
    if start is None:
        return "No '## [Unreleased]' section in CHANGELOG.md"
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("## [")),
        len(lines),
    )

    # A '###' inside a fenced block is sample text, not a section heading.
    headings: list[str] = []
    fenced = has_content = False
    for line in lines[start + 1 : end]:
        if re.match(r"^(```|~~~)", line.strip()):
            fenced = not fenced
        if not fenced and line.startswith("### "):
            headings.append(line[4:].strip())
            continue
        if line.strip():
            has_content = True

    if require_content and not has_content:
        return (
            "[Unreleased] is empty. release-prep only renames the header, so "
            "releasing now would ship a blank section and blank GitHub Release "
            "notes. Author the entries first — `git log v<PREV>..HEAD` lists "
            "what landed."
        )

    if dupes := sorted({h for h in headings if headings.count(h) > 1}):
        return (
            f"[Unreleased] has duplicate sections: {dupes}. Merge each pair "
            "into one, or the duplicates ship inside the release section."
        )

    if unknown := [h for h in headings if _key(h) not in ORDER]:
        return (
            f"[Unreleased] has unrecognised sections: {unknown}. "
            f"Expected some of {ORDER}."
        )

    indices = [ORDER.index(_key(h)) for h in headings]
    if indices != sorted(indices):
        expected = [h for h in ORDER if h in {_key(x) for x in headings}]
        return (
            f"[Unreleased] sections are out of order: {headings}. Expected: {expected}"
        )

    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--file",
        default="CHANGELOG.md",
        type=pathlib.Path,
        help="changelog to validate (default: CHANGELOG.md)",
    )
    parser.add_argument(
        "--require-content",
        action="store_true",
        help="also fail when [Unreleased] is empty (release-prep only)",
    )
    args = parser.parse_args()

    text = args.file.read_text(encoding="utf-8")
    error = validate(text, require_content=args.require_content)
    if error is not None:
        print(f"::error::{error}")
        return 1
    print("[Unreleased] OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
