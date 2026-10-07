#!/usr/bin/env python3
"""Compute the Docker Hub tags a release image is pushed under.

    git tag --list 'v*' | python3 scripts/release_image_tags.py v1.2.3

Prints ``version=1.2.3`` and ``tags=<comma-separated image refs>`` in the
``$GITHUB_OUTPUT`` format, for publish.yml's docker-publish job.

The exact version is always tagged. Each moving alias is tagged only when this
release is the highest release tag it covers:

- ``X.Y``    when no higher ``vX.Y.*`` tag exists,
- ``X``      when no higher ``vX.*.*`` tag exists, and only from 1.0.0 on
             (v0 releases publish no major alias, mirroring action-major-tag),
- ``latest`` when no higher release tag exists at all.

docker/metadata-action, which this replaces, adds ``latest`` and every alias
for any non-prerelease tag. That is right for the newest release and wrong for
any other: publishing a backport, or republishing an older version through the
workflow_dispatch path, would move ``latest`` and the aliases backwards.

The tag under release must be in the list read from stdin. An empty or
truncated list (a shallow checkout, a failed ``git tag``) fails loudly rather
than computing aliases against nothing.
"""

from __future__ import annotations

import re
import sys

IMAGE = "composelint/compose-lint"
_RELEASE_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")

Version = tuple[int, int, int]


def parse(tag: str) -> Version | None:
    """``v1.2.3`` -> ``(1, 2, 3)``; anything else (``v1``, ``v1.2.3-rc1``) -> None."""
    match = _RELEASE_TAG.match(tag)
    if match is None:
        return None
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def image_tags(tag: str, existing: list[str]) -> list[str]:
    """The tags to push for release ``tag``, given every tag in the repository."""
    version = parse(tag)
    if version is None:
        raise ValueError(f"{tag!r} is not a release tag (expected vX.Y.Z)")
    releases = {v for v in (parse(t.strip()) for t in existing) if v is not None}
    if version not in releases:
        raise ValueError(
            f"{tag} is not among the repository's release tags; the tag list is "
            "empty or incomplete (shallow checkout?)"
        )
    major, minor, patch = version
    names = [f"{major}.{minor}.{patch}"]
    if version == max(v for v in releases if v[:2] == (major, minor)):
        names.append(f"{major}.{minor}")
    if major >= 1 and version == max(v for v in releases if v[0] == major):
        names.append(f"{major}")
    if version == max(releases):
        names.append("latest")
    return [f"{IMAGE}:{name}" for name in names]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: git tag --list 'v*' | release_image_tags.py vX.Y.Z", file=sys.stderr)
        return 2
    tag = argv[1]
    try:
        tags = image_tags(tag, sys.stdin.read().splitlines())
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    print(f"version={tag[1:]}")
    print(f"tags={','.join(tags)}")
    print(f"{tag} -> {', '.join(tags)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
