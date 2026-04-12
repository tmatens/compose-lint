#!/usr/bin/env bash
# Bump the version in pyproject.toml and src/compose_lint/__init__.py.
# Usage: scripts/bump-version.sh X.Y.Z
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 X.Y.Z" >&2
    exit 1
fi

version="$1"
if ! echo "${version}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "Error: invalid version '${version}'. Expected X.Y.Z" >&2
    exit 1
fi

root="$(git rev-parse --show-toplevel)"

sed -i "s/^version = \".*\"/version = \"${version}\"/" "${root}/pyproject.toml"
sed -i "s/^__version__ = \".*\"/__version__ = \"${version}\"/" "${root}/src/compose_lint/__init__.py"

echo "Bumped to ${version}:"
grep '^version' "${root}/pyproject.toml"
grep '__version__' "${root}/src/compose_lint/__init__.py"
echo ""
echo "Next: update CHANGELOG.md, then:"
echo "  git add pyproject.toml src/compose_lint/__init__.py CHANGELOG.md"
echo "  git commit -S -m 'Prepare ${version} release'"
