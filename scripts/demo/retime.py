#!/usr/bin/env python3
"""Compact a VHS demo GIF by collapsing static frame runs, preserving timing.

VHS records the cast faithfully: 25 fps of 40ms frames whose total matches the
tape's `Sleep` directives, with the terminal's own cursor blink captured in it
(~600ms per phase, solid while typing, as a real terminal behaves). What it
does not do is deduplicate — a multi-second read-pause is stored as ~150
byte-identical frames.

So this script does one thing: merge each run of visually identical frames into
a single frame carrying the run's summed duration. That is lossless in both
timing and appearance — the output plays for exactly as long as the input, and
every frame shown is a frame VHS captured. On the README cast it turns 615
frames into 75 with no visible difference.

The blink therefore comes from the recording rather than being synthesized, and
pacing is controlled where it belongs: the `Sleep` values in the tape.

Historical note: this script used to drop frames and rebuild the pauses with a
synthesized blink, on the premise that VHS collapsed `Sleep` timings and
rendered a steady cursor. Measured against the current toolchain that premise
does not hold, and the synthesis had a visible cost — a hold could land on the
blink's off-phase and freeze a cursorless screen for ~2s.

Usage: retime.py [--min-seconds S] INPUT.gif OUTPUT.gif
"""

from __future__ import annotations

import argparse

from PIL import Image, ImageChops

# Below this fraction of changed pixels two frames are "the same". Well under a
# single typed character (~0.03%) and an order of magnitude under the cursor
# block (~0.05%), so neither typing nor the blink is ever merged away.
EPS = 0.00004


def changed_fraction(a: Image.Image, b: Image.Image, total: int) -> float:
    """Fraction of pixels that meaningfully differ between two RGB frames."""
    diff = ImageChops.difference(a, b).convert("L")
    return diff.point(lambda p: 255 if p > 40 else 0).histogram()[255] / total


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("input", help="raw GIF recorded by VHS")
    p.add_argument("output", help="compacted GIF to write")
    p.add_argument(
        "--min-seconds",
        type=float,
        default=0.0,
        help="fail if the cast is shorter than this. Guards against a VHS "
        "regression that collapses Sleep timings, which would otherwise ship a "
        "GIF that flashes past unreadably.",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    src = Image.open(args.input)
    n = src.n_frames
    frames: list[Image.Image] = []
    durations: list[int] = []
    for i in range(n):
        src.seek(i)
        frames.append(src.convert("RGB"))
        durations.append(src.info.get("duration") or 0)
    total = src.size[0] * src.size[1]

    raw_seconds = sum(durations) / 1000
    if raw_seconds < args.min_seconds:
        print(
            f"error: cast is {raw_seconds:.1f}s, expected at least "
            f"{args.min_seconds:.1f}s. VHS did not honor the tape's Sleep "
            f"timings; the GIF would be unreadable.",
        )
        return 1

    # Merge each run of identical frames into its first frame, accumulating the
    # run's duration. Comparing against the last *kept* frame (not the previous
    # one) is what makes a long static run collapse to a single entry.
    kept: list[int] = []
    merged: list[int] = []
    for i in range(n):
        if kept and changed_fraction(frames[i], frames[kept[-1]], total) <= EPS:
            merged[-1] += durations[i]
        else:
            kept.append(i)
            merged.append(durations[i])

    # One global palette covering every color in the cast. Derive it from the
    # most colorful frame (the findings screen, with its red/yellow severity
    # colors) stacked with the final frame, so quantizing doesn't grey out the
    # severity colors a plainer frame's palette would omit.
    shown = [frames[i] for i in kept]
    richest = max(shown, key=lambda f: len(f.getcolors(maxcolors=1 << 16) or [(0, 0)]))
    sample = Image.new("RGB", (richest.width, richest.height * 2))
    sample.paste(richest, (0, 0))
    sample.paste(shown[-1], (0, richest.height))
    palette = sample.quantize(colors=256, method=Image.MEDIANCUT)

    pframes = []
    for img in shown:
        pf = img.quantize(palette=palette, dither=Image.NONE)
        pf.info.pop("transparency", None)  # avoid a Pillow GIF-save crash
        pframes.append(pf)

    pframes[0].save(
        args.output,
        save_all=True,
        append_images=pframes[1:],
        duration=merged,
        loop=0,
        optimize=True,
    )
    print(
        f"{n} -> {len(kept)} frames  ·  total {sum(merged) / 1000:.1f}s "
        f"(unchanged from the recording)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
