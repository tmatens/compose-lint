#!/usr/bin/env bash
# Bump the three source-of-truth version files: pyproject.toml,
# src/compose_lint/__init__.py, and action.yml's DEFAULT_VERSION (the package
# the Action installs when a consumer does not pass `version:`). README
# snippets and the CHANGELOG are handled by hand per the docs/RELEASING.md
# "Bump the version" checklist.
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
# tests/test_action_contract.py fails if this drifts from __version__, so a
# missed bump here is caught before release rather than shipping an Action that
# installs a different linter than it claims.
sed -i "s/^\( *\)DEFAULT_VERSION=\".*\"/\1DEFAULT_VERSION=\"${version}\"/" "${root}/action.yml"

# The PyPI "Development Status" classifier follows the major version: 1.x and
# later are Production/Stable, 0.x is Beta. docs/RELEASING.md "Cutting 1.0.0"
# requires the flip in the same commit as the version bump, and
# tests/test_release_layer.py fails the PR if the two disagree -- PyPI metadata
# is immutable per version, so a 1.0.0 published as Beta stays Beta forever.
# Set, not flip: the line is rewritten to whatever the major implies, so the
# result does not depend on what the checkout held before the bump.
major="${version%%.*}"
if [ "${major}" -ge 1 ]; then
    status="5 - Production\/Stable"
else
    status="4 - Beta"
fi
sed -i "s/\"Development Status :: [^\"]*\"/\"Development Status :: ${status}\"/" "${root}/pyproject.toml"

echo "Bumped to ${version}:"
grep '^version' "${root}/pyproject.toml"
grep '__version__' "${root}/src/compose_lint/__init__.py"
grep 'DEFAULT_VERSION=' "${root}/action.yml"
grep 'Development Status' "${root}/pyproject.toml"
echo ""
echo "Still to do by hand (see docs/RELEASING.md 'Bump the version'):"
echo "  - README.md snippets: pre-commit rev:, pip ==, docker tag, Action # vX.Y.Z"
echo "  - CHANGELOG.md: author the ${version} entry"
echo "Then:"
echo "  git add pyproject.toml src/compose_lint/__init__.py action.yml README.md CHANGELOG.md"
echo "  git commit -S -m 'Prepare ${version} release'"
