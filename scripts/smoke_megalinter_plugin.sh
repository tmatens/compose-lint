#!/usr/bin/env bash
# Run MegaLinter with the compose-lint plugin on the plugin's two fixtures and
# check the verdicts. This is ci.yml's `megalinter-plugin` job; it runs the
# same way from a checkout.
#
#   scripts/smoke_megalinter_plugin.sh IMAGE WHEEL
#
# IMAGE is a MegaLinter image and WHEEL a built compose-lint wheel. Needs
# Docker and network access, because the wheel's one dependency comes from
# PyPI inside the container.
#
# The descriptor users load installs the compose-lint release it pins, from
# PyPI. That release does not exist yet on the pull request that prepares it,
# and a run against the previous release would not test the working tree. So
# this run swaps the pinned requirement for the wheel built from the checkout
# and leaves every other line of the descriptor as users get it. The literal
# install line is the one part this does not exercise.
set -euo pipefail

image=${1:?usage: smoke_megalinter_plugin.sh IMAGE WHEEL}
wheel=${2:?usage: smoke_megalinter_plugin.sh IMAGE WHEEL}
here=$(cd "$(dirname "$0")/.." && pwd)
plugin_dir=mega-linter-plugin-compose-lint
descriptor=compose-lint.megalinter-descriptor.yml
wheel_name=$(basename "$wheel")
work=$(mktemp -d)
trap 'rm -rf "$work" 2>/dev/null || true' EXIT

status=0
for fixture in good bad; do
  ws=$work/$fixture
  mkdir -p "$ws/$plugin_dir" "$ws/wheel"
  cp "$here/$plugin_dir/fixtures/$fixture/compose.yml" "$ws/compose.yml"
  cp "$wheel" "$ws/wheel/$wheel_name"
  sed -E "s|\"compose-lint==[0-9]+\.[0-9]+\.[0-9]+\"|/tmp/lint/wheel/$wheel_name|" \
    "$here/$plugin_dir/$descriptor" >"$ws/$plugin_dir/$descriptor"
  if ! grep -q "/tmp/lint/wheel/$wheel_name" "$ws/$plugin_dir/$descriptor"; then
    echo "::error::the descriptor's install line no longer has the pinned requirement this script replaces"
    exit 1
  fi

  rc=0
  docker run --rm --log-driver none \
    -v "$ws:/tmp/lint" \
    -e DEFAULT_WORKSPACE=/tmp/lint \
    -e VALIDATE_ALL_CODEBASE=true \
    -e REPORT_OUTPUT_FOLDER=none \
    -e PRINT_ALPACA=false \
    -e "PLUGINS=file://$plugin_dir/$descriptor" \
    -e ENABLE_LINTERS=COMPOSE_COMPOSE_LINT \
    "$image" >"$work/$fixture.log" 2>&1 || rc=$?

  if [ "$fixture" = good ]; then
    want_rc=0
    want_line='Linted \[COMPOSE\] files with \[compose-lint\] successfully'
  else
    want_rc=1
    want_line='Linted \[COMPOSE\] files with \[compose-lint\]: Found 3 error\(s\)'
  fi
  if [ "$rc" -eq "$want_rc" ] && grep -qE "$want_line" "$work/$fixture.log"; then
    echo "ok: $fixture fixture, MegaLinter exit $rc"
  else
    echo "::error::$fixture fixture: MegaLinter exit $rc, expected $want_rc and a line matching: $want_line"
    cat "$work/$fixture.log"
    status=1
  fi
done
exit "$status"
