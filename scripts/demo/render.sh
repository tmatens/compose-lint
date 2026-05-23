#!/usr/bin/env bash
# Regenerate the README demo GIF (docs/assets/demo.gif) from demo.tape.
#
# Two steps, both inside the pinned toolchain image so the only host
# requirement is Docker:
#   1. VHS records demo.tape -> scripts/demo/demo.gif (raw; timing collapsed,
#      see retime.py for why).
#   2. retime.py re-times it -> docs/assets/demo.gif (the committed asset).
#
# Usage: scripts/demo/render.sh
set -euo pipefail

repo="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
image="compose-lint-demo"

docker build -t "$image" "$repo/scripts/demo"

# 1. Record. CWD is the demo dir so `compose-lint docker-compose.yml` resolves.
docker run --rm -v "$repo:/repo" -w /repo/scripts/demo "$image" demo.tape

# 2. Re-time into the committed asset path.
docker run --rm -v "$repo:/repo" -w /repo --entrypoint python3 "$image" \
    scripts/demo/retime.py scripts/demo/demo.gif docs/assets/demo.gif

echo "Wrote docs/assets/demo.gif"
