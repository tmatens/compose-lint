#!/usr/bin/env bash
# Bump the two source-of-truth version files: pyproject.toml and
# src/compose_lint/__init__.py. README snippets and the CHANGELOG are handled
# by hand per the docs/RELEASING.md "Bump the version" checklist.
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
echo "Still to do by hand (see docs/RELEASING.md 'Bump the version'):"
echo "  - README.md snippets: pre-commit rev:, pip ==, docker tag, Action # vX.Y.Z"
echo "  - CHANGELOG.md: author the ${version} entry"
echo "Then:"
echo "  git add pyproject.toml src/compose_lint/__init__.py README.md CHANGELOG.md"
echo "  git commit -S -m 'Prepare ${version} release'"
