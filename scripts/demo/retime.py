#!/usr/bin/env python3
"""Re-time the VHS demo GIF so the read-pauses are actually readable.

VHS (v0.11.0) drops frames while rendering compose-lint's heavy colored output
under load and assigns each surviving frame a fixed delay, which collapses the
`Sleep` pauses — the whole cast ends up playing in ~4.5s with no time to read
the findings. This script keeps the typing/reveal animation untouched and
restores a long hold on each "settled output" frame.

Detection is structural, not hard-coded to frame indices, so it survives a
re-render against a newer compose-lint:

* Static frames and the blinking-cursor oscillation (A B A B ...) are dropped —
  a frame is redundant if it nearly matches the previous frame *or* the one
  before it.
* A "reveal" is a frame whose change from the previous kept frame covers a large
  share of the screen (command output painting in). The last frame of each
  reveal burst is a "settled output" frame and gets a long hold.

Usage: retime.py INPUT.gif OUTPUT.gif
"""

from __future__ import annotations

import sys

from PIL import Image, ImageChops

# Durations (ms).
LEAD = 1000  # initial prompt before typing starts
TYPE = 55  # per typing / scroll frame
PAUSE_BEFORE_RUN = 2500  # pause on the fully-typed command, before it runs
HOLD_LINT = 8000  # read the findings
HOLD_FINAL = 9000  # read the rule docs on the last frame

# Thresholds as a fraction of total pixels.
EPS = 0.00004  # below this a frame is "the same" (well under one typed character)
BIG = 0.04  # above this an incoming change is a content "reveal" (sparse terminal
# text reveals only ~6% of pixels, so this sits well below that but far above the
# ~0.03% of a typed character)


def changed_fraction(a: Image.Image, b: Image.Image, total: int) -> float:
    """Fraction of pixels that meaningfully differ between two RGB frames.

    A per-pixel luminance threshold ignores faint antialiasing noise, so a
    single typed character still registers regardless of font size.
    """
    diff = ImageChops.difference(a, b).convert("L")
    mask = diff.point(lambda p: 255 if p > 40 else 0)
    return mask.histogram()[255] / total


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src = Image.open(sys.argv[1])
    n = src.n_frames
    frames = []
    for i in range(n):
        src.seek(i)
        frames.append(src.convert("RGB"))
    w, h = src.size
    total = w * h

    # Drop static frames and blinking-cursor oscillation.
    kept = [0]
    for i in range(1, n):
        d_prev = changed_fraction(frames[i], frames[i - 1], total)
        d_prev2 = changed_fraction(frames[i], frames[i - 2], total) if i >= 2 else 1.0
        if d_prev > EPS and d_prev2 > EPS:
            kept.append(i)

    # Incoming change for each kept frame, relative to the previous kept frame.
    incoming = [1.0]
    for k in range(1, len(kept)):
        incoming.append(changed_fraction(frames[kept[k]], frames[kept[k - 1]], total))

    # Pacing:
    #   * a short beat once a command is fully typed, before it runs (the frame
    #     just before a reveal);
    #   * two longer read-pauses: the first settled output (the lint findings)
    #     and the final frame (the rule docs).
    # A settled-output frame is a reveal whose successor is not itself a reveal —
    # i.e. the output has finished painting. Only the first is held mid-cast; the
    # explain output is covered by the final-frame hold, which also absorbs the
    # trailing shell-prompt frame.
    durations = []
    held_mid = False
    for k in range(len(kept)):
        is_reveal = incoming[k] > BIG
        next_is_reveal = (k + 1 < len(kept)) and incoming[k + 1] > BIG
        if k == 0:
            durations.append(LEAD)
        elif k == len(kept) - 1:
            durations.append(HOLD_FINAL)
        elif is_reveal and not next_is_reveal and not held_mid:
            durations.append(HOLD_LINT)
            held_mid = True
        elif next_is_reveal and not is_reveal:
            durations.append(PAUSE_BEFORE_RUN)
        else:
            durations.append(TYPE)

    out = [frames[i] for i in kept]
    palette = out[-1].quantize(colors=256, method=Image.MEDIANCUT)
    pframes = []
    for f in out:
        pf = f.quantize(palette=palette, dither=Image.NONE)
        pf.info.pop("transparency", None)  # avoid a Pillow GIF-save crash
        pframes.append(pf)

    pframes[0].save(
        sys.argv[2],
        save_all=True,
        append_images=pframes[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    print(f"kept {len(out)}/{n} frames  ·  total {sum(durations) / 1000:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
