#!/usr/bin/env python3
"""Re-time the VHS demo GIF so the read-pauses are readable and visibly alive.

VHS (v0.11.0) drops frames while rendering compose-lint's heavy colored output
under load and assigns each surviving frame a fixed delay, which collapses the
`Sleep` pauses — the whole cast ends up playing in ~4.5s with no time to read
the findings. This script keeps the typing/reveal animation, then rebuilds each
pause as a long hold with a *blinking cursor* so the GIF never looks frozen.

The blink is synthesized, not captured: VHS renders a steady block cursor and
drops frames unpredictably, so relying on it to capture an on/off cursor is a
lottery. Instead we detect the steady cursor block in the held frame (the most
solidly filled character cell) and toggle it off and on ourselves.

Structure detection is positional-free, so it survives a re-render against a
newer compose-lint:

* Static frames and near-duplicates are dropped from the animation.
* A "reveal" is a frame whose change from the previous kept frame covers a large
  share of the screen (command output painting in). The last frame of a reveal
  burst is a "settled output" frame and gets a long hold.

Usage: retime.py INPUT.gif OUTPUT.gif
"""

from __future__ import annotations

import sys

import numpy as np
from PIL import Image, ImageChops, ImageDraw

# Durations (ms).
LEAD = 1000  # initial prompt before typing starts
TYPE = 55  # per typing / scroll frame
PAUSE_BEFORE_RUN = 1900  # pause on the fully-typed command, before it runs
HOLD_LINT = 8000  # read the findings
HOLD_FINAL = 9000  # read the rule docs on the last frame
BLINK = 530  # half the cursor-blink cycle within a hold

# Thresholds as a fraction of total pixels.
EPS = 0.00004  # below this a frame is "the same" (well under one typed character)
BIG = 0.04  # above this an incoming change is a content "reveal" (sparse terminal
# text reveals only ~6% of pixels, so this sits well below that but far above the
# ~0.03% of a typed character)

# Cursor cell geometry at FontSize 22 (px). The detector probes a window a little
# inside the cell so only a fully-filled block (the cursor) scores ~1.0.
CELL_W, CELL_H = 14, 30
PROBE_W, PROBE_H = 10, 22
CURSOR_FILL = 0.7  # min fill ratio for the probe window to count as the cursor


def changed_mask(a: Image.Image, b: Image.Image) -> Image.Image:
    """Binary mask of pixels that meaningfully differ between two RGB frames."""
    diff = ImageChops.difference(a, b).convert("L")
    return diff.point(lambda p: 255 if p > 40 else 0)


def changed_fraction(a: Image.Image, b: Image.Image, total: int) -> float:
    """Fraction of pixels that meaningfully differ between two RGB frames."""
    return changed_mask(a, b).histogram()[255] / total


def background_color(frame: Image.Image) -> tuple[int, int, int]:
    """The most common color — the terminal background."""
    colors = frame.getcolors(maxcolors=1 << 20) or [(1, (0, 0, 0))]
    return max(colors)[1]


def detect_cursor(frame: Image.Image):
    """Bounding box of the block cursor (the most solidly filled cell), or None."""
    bright = (np.asarray(frame.convert("L"), dtype=np.float32) > 120).astype(np.float32)
    # Summed-area table for O(1) window sums.
    sat = np.zeros((bright.shape[0] + 1, bright.shape[1] + 1), dtype=np.float32)
    sat[1:, 1:] = bright.cumsum(0).cumsum(1)
    h, w = bright.shape
    window = (
        sat[PROBE_H:, PROBE_W:]
        - sat[:-PROBE_H, PROBE_W:]
        - sat[PROBE_H:, :-PROBE_W]
        + sat[:-PROBE_H, :-PROBE_W]
    )
    fill = window / (PROBE_W * PROBE_H)
    y, x = np.unravel_index(int(fill.argmax()), fill.shape)
    if fill[y, x] < CURSOR_FILL:
        return None
    # The probe sits inside the block; pad out to the full cell, clamped.
    x0, y0 = max(0, int(x) - 3), max(0, int(y) - 4)
    return (x0, y0, min(w, x0 + CELL_W + 4), min(h, y0 + CELL_H + 4))


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
    bg = background_color(frames[-1])

    # Drop static frames and near-duplicates from the animation.
    kept = [0]
    for i in range(1, n):
        d_prev = changed_fraction(frames[i], frames[i - 1], total)
        d_prev2 = changed_fraction(frames[i], frames[i - 2], total) if i >= 2 else 1.0
        if d_prev > EPS and d_prev2 > EPS:
            kept.append(i)

    incoming = [1.0]
    for k in range(1, len(kept)):
        incoming.append(changed_fraction(frames[kept[k]], frames[kept[k - 1]], total))

    def hold(seq, base: Image.Image, ms: int):
        """Fill `ms` by blinking the cursor in `base`, or hold it still."""
        bbox = detect_cursor(base)
        if bbox is None:
            seq.append((base, ms))
            return
        off = base.copy()
        ImageDraw.Draw(off).rectangle(bbox, fill=bg)
        states, t, i = (base, off), 0, 0
        while t < ms:
            step = min(BLINK, ms - t)
            seq.append((states[i % 2], step))
            t, i = t + step, i + 1

    # Pacing: a beat once a command is fully typed (the frame before a reveal),
    # then two longer read-pauses — the first settled output (the lint findings)
    # and the final frame (the rule docs). Only the first read-pause is held
    # mid-cast; the explain output is covered by the final-frame hold.
    seq: list[tuple[Image.Image, int]] = []
    held_mid = False
    for k in range(len(kept)):
        ri = kept[k]
        is_reveal = incoming[k] > BIG
        next_is_reveal = (k + 1 < len(kept)) and incoming[k + 1] > BIG
        if k == 0:
            hold(seq, frames[0], LEAD)
        elif k == len(kept) - 1:
            hold(seq, frames[n - 1], HOLD_FINAL)  # last raw frame = settled prompt
        elif is_reveal and not next_is_reveal and not held_mid:
            # A settled frame after the reveal, not the reveal itself (whose
            # cursor is still mid-output).
            hold(seq, frames[min(ri + 2, n - 1)], HOLD_LINT)
            held_mid = True
        elif next_is_reveal and not is_reveal:
            # Short beat on the fully-typed command. The cursor sits at the end
            # of a long command line here, which the block detector can't pin
            # down reliably, so hold it steady rather than blink the wrong cell.
            seq.append((frames[ri], PAUSE_BEFORE_RUN))
        else:
            seq.append((frames[ri], TYPE))

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

    cache: dict[int, Image.Image] = {}

    def quantized(img: Image.Image) -> Image.Image:
        if id(img) not in cache:
            pf = img.quantize(palette=palette, dither=Image.NONE)
            pf.info.pop("transparency", None)  # avoid a Pillow GIF-save crash
            cache[id(img)] = pf
        return cache[id(img)]

    pframes = [quantized(img) for img, _ in seq]
    durations = [ms for _, ms in seq]

    pframes[0].save(
        sys.argv[2],
        save_all=True,
        append_images=pframes[1:],
        duration=durations,
        loop=0,
        optimize=True,
    )
    print(f"{len(seq)} frames  ·  total {sum(durations) / 1000:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
