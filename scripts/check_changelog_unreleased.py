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

It also requires every ``### Security`` entry to record whether it got an
advisory, so the decision in .github/SECURITY.md is made on the PR that
fixes the defect rather than remembered at release time.

With ``--base-image-since <ref>`` (release-prep only) it also requires an
entry when the Dockerfile's runtime base digest differs from the one at
``<ref>`` (#1234). Those repins merge through the digest age gate with no
human PR, so nothing else prompts an entry; six of the nine releases that
moved the base between 0.20.0 and 1.3.0 shipped without one. It runs at
dispatch only, because a repin mid-cycle is not yet a release.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
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

    if undecided := _undecided_security_entries(lines[start + 1 : end]):
        return (
            f"[Unreleased] ### Security has {len(undecided)} entry(s) with no "
            "advisory decision. End each one with the advisory it fixes "
            "(`See GHSA-xxxx-xxxx-xxxx.`) or `No advisory:` and the reason, per "
            ".github/SECURITY.md. First one: " + repr(undecided[0][:80])
        )

    return None


_GHSA = re.compile(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}")


def _undecided_security_entries(section: list[str]) -> list[str]:
    """Top-level ``### Security`` bullets that record no advisory decision.

    Only ``[Unreleased]`` is passed in, so entries already released under the
    older convention are never re-judged. A bullet runs until the next
    top-level bullet or heading; its continuation lines count.
    """
    entries: list[str] = []
    inside = fenced = False
    for line in section:
        if re.match(r"^(```|~~~)", line.strip()):
            fenced = not fenced
        if fenced:
            continue
        if line.startswith("### "):
            inside = line[4:].strip() == "Security"
            continue
        if not inside:
            continue
        if line.startswith("- "):
            entries.append(line)
        elif entries and line.strip():
            entries[-1] += " " + line.strip()
    return [e for e in entries if not _GHSA.search(e) and "No advisory:" not in e]


_FROM_DIGEST = re.compile(r"^FROM\s+(\S+?)@sha256:([0-9a-f]{64})", re.IGNORECASE)


def runtime_base(dockerfile: str) -> tuple[str, str] | None:
    """``(image, digest)`` of the last ``FROM``: the stage that ships.

    Earlier stages (the ``debian:13-slim`` build stage) never reach the
    published image, so a repin there needs no entry.
    """
    found = None
    for line in dockerfile.splitlines():
        if m := _FROM_DIGEST.match(line.strip()):
            found = (m.group(1), m.group(2))
    return found


def missing_base_repin_entry(text: str, dockerfile: str, previous: str) -> str | None:
    """Error when the runtime base moved since ``previous`` with no entry.

    The entry is matched on ``sha256:`` plus the new digest's first eight hex
    digits, the form every existing entry uses (``sha256:1c32c372…``).
    """
    now, then = runtime_base(dockerfile), runtime_base(previous)
    if now is None or then is None or now[1] == then[1]:
        return None
    lines = text.splitlines()
    start = next(
        (i for i, ln in enumerate(lines) if ln.startswith("## [Unreleased]")), None
    )
    if start is None:
        return None  # validate() already reports this
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("## [")),
        len(lines),
    )
    short = f"sha256:{now[1][:8]}"
    if any(short in ln for ln in lines[start + 1 : end]):
        return None
    return (
        f"The runtime base {now[0]} moved from sha256:{then[1][:8]}… to "
        f"{short}… since the last release, and [Unreleased] does not mention "
        f"{short}. It changes the published image, so add the standard entry "
        "under ### Changed in a PR and re-dispatch: '- **The published image "
        f"moves to a newer distroless base.** `{now[0]}` is repinned from "
        f"`sha256:{then[1][:8]}…` to `{short}…`, picking up the base image's "
        "own updates.'"
    )


def _git_show(ref: str, path: str) -> str:
    return subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


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
    parser.add_argument(
        "--base-image-since",
        metavar="REF",
        help="also fail when the Dockerfile's runtime base digest differs from "
        "the one at REF and [Unreleased] has no entry for it (release-prep only)",
    )
    args = parser.parse_args()

    text = args.file.read_text(encoding="utf-8")
    error = validate(text, require_content=args.require_content)
    if error is None and args.base_image_since:
        error = missing_base_repin_entry(
            text,
            pathlib.Path("Dockerfile").read_text(encoding="utf-8"),
            _git_show(args.base_image_since, "Dockerfile"),
        )
    if error is not None:
        print(f"::error::{error}")
        return 1
    print("[Unreleased] OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
