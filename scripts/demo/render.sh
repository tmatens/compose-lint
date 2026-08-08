#!/usr/bin/env bash
# Regenerate the README demo GIFs from their tapes.
#
# Two casts, both recorded inside the pinned toolchain image so the only host
# requirement is Docker:
#   demo.tape -> docs/assets/demo.gif      (hero: check + --explain)
#   fix.tape  -> docs/assets/demo-fix.gif  (fix: dry-run diff, --apply, re-check)
#
# Each is recorded by VHS, then compacted by retime.py — which merges runs of
# identical frames and leaves the recording's own timing (and cursor blink)
# alone. See retime.py's docstring.
#
# Usage: render.sh [demo|fix ...]     (default: both)
set -euo pipefail

repo="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
image="compose-lint-demo"

# Floor for each cast's runtime, a little under the sum of its tape's Sleeps.
# retime.py fails below this, so a VHS regression that collapses Sleep timings
# is caught here instead of shipping a GIF that flashes past unreadably.
declare -A min_seconds=([demo]=20 [fix]=18)
declare -A assets=([demo]="docs/assets/demo.gif" [fix]="docs/assets/demo-fix.gif")

casts=("$@")
[ ${#casts[@]} -eq 0 ] && casts=(demo fix)

for name in "${casts[@]}"; do
    if [ -z "${assets[$name]:-}" ]; then
        echo "unknown cast: $name (expected 'demo' or 'fix')" >&2
        exit 2
    fi
done

docker build -t "$image" "$repo/scripts/demo"

for name in "${casts[@]}"; do
    # 1. Record. CWD is the demo dir so the tape's fixture paths resolve.
    docker run --rm -v "$repo:/repo" -w /repo/scripts/demo "$image" "$name.tape"
    # 2. Compact into the committed asset path.
    docker run --rm -v "$repo:/repo" -w /repo --entrypoint python3 "$image" \
        scripts/demo/retime.py --min-seconds "${min_seconds[$name]}" \
        "scripts/demo/$name.gif" "${assets[$name]}"
    echo "Wrote ${assets[$name]}"
done
