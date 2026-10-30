# README demo GIFs

Source for the two animated demos embedded in the project README. Both
recordings are deterministic — they re-render identically from these files, so
they can be refreshed against any release.

| Cast       | Asset                     | Shows                                       |
| ---------- | ------------------------- | ------------------------------------------- |
| `demo.tape` | `docs/assets/demo.gif`     | `check` on a small file, then `--explain`   |
| `fix.tape`  | `docs/assets/demo-fix.gif` | `fix` dry-run diff, `--apply`, then re-lint |

## Files

| File                 | Purpose                                                       |
| -------------------- | ------------------------------------------------------------- |
| `render.sh`          | One-command regenerate (build + record + compact)             |
| `demo.tape`          | [VHS](https://github.com/charmbracelet/vhs) script, hero cast |
| `fix.tape`           | VHS script, fix cast                                          |
| `docker-compose.yml` | The ordinary-looking file the hero cast lints                 |
| `fix-compose.yml`    | The file the fix cast remediates                              |
| `Dockerfile`         | Toolchain: VHS + ttyd + ffmpeg + compose-lint + Pillow        |
| `requirements.in`    | Toolchain Python deps (compose-lint pin = recorded version)   |
| `requirements.lock`  | uv-compiled, hash-pinned resolve of `requirements.in`         |
| `retime.py`          | Compacts the raw recording (see below)                        |
| `expected_output.py` | Prints or checks the terminal text the casts show             |
| `expected-output.txt`| That text as recorded by the committed GIFs (banner masked)   |
| `frames.py`          | Writes five still frames of a GIF as PNGs, for review         |

## What each cast shows

**Hero** (`demo.tape`) lints `docker-compose.yml` — three findings, one per
tier: a CRITICAL mounted Docker socket (CL-0001) and a MEDIUM tag-only image
pin (CL-0019) on `watchtower`, and a HIGH plaintext credential (CL-0020,
`POSTGRES_PASSWORD`) on `db` — then runs `compose-lint --explain CL-0001` to
show the offline rule docs. Both services are otherwise hardened so only those
three fire; the report groups by service and severity-sorts within each, so the
CRITICAL socket finding, the one with the box-drawing underline, leads the
report above the `FAIL` verdict.

**Fix** (`fix.tape`) runs `compose-lint fix` on `fix-compose.yml`, an app
service that never had its hardening filled in. The dry run prints the three
`⚠ behavior-changing` caveats and the diff it *would* apply — `read_only`,
`no-new-privileges`, and rebinding the published port to `127.0.0.1` — writes
nothing, and lists the one finding it leaves to fix by hand with the fix to
make (CL-0019, a tag-only image pin: the digest is a value only the user can
supply). The second screen applies those
three edits and re-lints: `FAIL` becomes `PASS`, with the leftover MEDIUM still
reported rather than silently dropped. The cast copies the fixture to `/tmp`
before running, because `--apply` rewrites the file in place.

`tests/test_demo_fixture.py` pins both stories — the hero's finding set, and
the fix cast's auto-fixed/manual split and its FAIL→PASS flip — so a rule or
fixture change that would silently invalidate a GIF fails CI instead.

## Regenerate

**After a release this happens on its own.** `marketplace-smoke.yml`'s
`rerecord-demos` job runs the commands the tapes type against the released
wheel, compares the text with `expected-output.txt` (the version banner
masked), and if anything differs — or when dispatched with `force: true` —
renders both casts, moves the pin and lock, rewrites the snapshot and opens a
PR with the recordings embedded for a human to look at and merge. The
snapshot is written only as part of a re-record, by that job or by the steps
below; it records what the GIFs show, not what the source tree prints today.

By hand, Docker is the only requirement (the toolchain image bundles
everything else):

```bash
scripts/demo/render.sh          # both casts
scripts/demo/render.sh fix      # just one
```

This builds the toolchain image, records each tape to a gitignored intermediate
(`scripts/demo/{demo,fix}.gif`), then compacts it into the committed asset.

To record a newer compose-lint, bump the `compose-lint==` pin in
`requirements.in` and recompile the lock (the exact command is in the lock
file's header):

```bash
uv pip compile scripts/demo/requirements.in --python-version=3.13 \
    --generate-hashes --output-file=scripts/demo/requirements.lock
```

Then record the text the new GIFs show, so the next release is compared
against them:

```bash
scripts/demo/expected_output.py --compose-lint <the released compose-lint> \
    --write scripts/demo/expected-output.txt
```

The pin records which release the committed GIFs were rendered on — the banner
in the hero cast shows that version. Renovate keeps pillow/numpy fresh in the
lock but deliberately never touches the compose-lint pin.

Because the toolchain installs from PyPI, a cast can only ever show a
*released* version — so a change to rule output is re-recorded **after** the
release that ships it, as the demo step in `docs/RELEASING.md` describes.

Each cast is sized to its output in the tape's `Set Height`, and the arithmetic
is written down beside it. After rendering, check neither screen scrolled: a
release that adds a line to `check` or `fix` output overflows the terminal and
silently cuts the top of the screen off. Raise the tape's `Height` by 30px per
extra row and re-render, then check the background is one flat color: at some
heights (970 was one) VHS paints alternate rows a shade off the window, and the
GIF palette turns that into faint horizontal stripes. 940 and 1000 are clean.

Bump the digest-pinned VHS base image via Renovate, same as any other base
image (see CLAUDE.md).

## Why `retime.py`

VHS records the cast faithfully — 25 fps of 40ms frames whose total matches the
tape's `Sleep` directives, with the terminal's own cursor blink captured in it
(~600ms per phase, and solid while typing, as a real terminal behaves). What it
does not do is deduplicate: a multi-second read-pause is stored as ~150
byte-identical frames.

So `retime.py` merges each run of identical frames into one frame carrying the
run's summed duration. That is lossless in both timing and appearance — the
output plays for exactly as long as the recording, and every frame shown is a
frame VHS captured. On the hero cast it turns 615 frames into 75.

**Pacing therefore lives in the tapes**, in their `Sleep` values, not in this
script. If a read-pause is too short, lengthen the `Sleep`.

This replaced an earlier approach that dropped frames and rebuilt the pauses
with a *synthesized* blink, on the premise that VHS collapsed `Sleep` timings
and rendered a steady cursor. Measured against the current toolchain that
premise does not hold, and the synthesis had a visible cost: a rebuilt hold
could land on the blink's off-phase and freeze a cursorless screen for ~2s.
`render.sh` passes `--min-seconds` per cast so that if a future VHS really does
collapse the timings, the render fails instead of shipping a GIF that flashes
past unreadably.
