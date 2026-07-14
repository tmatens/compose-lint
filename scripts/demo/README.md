# README demo GIF

Source for the animated demo embedded at the top of the project README
(`docs/assets/demo.gif`). The recording is deterministic — it re-renders
identically from these files, so it can be refreshed against any release.

## Files

| File                 | Purpose                                                       |
| -------------------- | ------------------------------------------------------------ |
| `render.sh`          | One-command regenerate (build + record + re-time)            |
| `demo.tape`          | [VHS](https://github.com/charmbracelet/vhs) recording script |
| `docker-compose.yml` | The small, ordinary-looking file the demo lints              |
| `Dockerfile`         | Toolchain: VHS + ttyd + ffmpeg + compose-lint + Pillow       |
| `requirements.in`    | Toolchain Python deps (compose-lint pin = recorded version)  |
| `requirements.lock`  | uv-compiled, hash-pinned resolve of `requirements.in`        |
| `retime.py`          | Restores readable read-pauses (see below)                    |

The demo lints `docker-compose.yml` (three findings: a CRITICAL mounted Docker
socket, a HIGH sensitive host mount, and a MEDIUM tag-only image pin), then runs
`compose-lint --explain CL-0001` to show the offline rule docs. The service is
mostly hardened so only those three findings fire; severity-sort puts the
CRITICAL socket finding — the one with the box-drawing underline — at the top,
leading the report above the `FAIL` verdict. `tests/test_demo_fixture.py` pins
this finding set, so a rule or fixture change that would silently change the
demo's story fails CI instead.

## Regenerate

Requires Docker only (the toolchain image bundles everything else):

```bash
scripts/demo/render.sh
```

This builds the toolchain image, records `demo.tape` to `scripts/demo/demo.gif`
(a gitignored intermediate), then re-times it into the committed asset at
`docs/assets/demo.gif`.

To record a newer compose-lint, bump the `compose-lint==` pin in
`requirements.in` and recompile the lock (the exact command is in the lock
file's header):

```bash
uv pip compile scripts/demo/requirements.in --python-version=3.13 \
    --generate-hashes --output-file=scripts/demo/requirements.lock
```

Keep the banner version the cast shows in step with the README's example
output. Renovate keeps pillow/numpy fresh in the lock but deliberately never
touches the compose-lint pin — it records which release the committed GIF was
rendered on.

Bump the digest-pinned VHS base image via Renovate, same as any other base
image (see CLAUDE.md).

## Why `retime.py`

VHS v0.11.0 drops frames while rendering compose-lint's colored output under
load and gives each surviving frame a fixed delay. That collapses the tape's
`Sleep` pauses — the raw GIF plays in ~4.5s with no time to read the findings.
`retime.py` keeps the typing/reveal animation, drops the static and
blinking-cursor frames, and restores a multi-second hold on the two settled
outputs (the findings and the rule docs). Detection is structural, not pinned
to frame numbers, so it survives a re-render against a newer compose-lint.
