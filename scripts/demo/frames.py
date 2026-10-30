#!/usr/bin/env python3
"""Write five still frames from each demo GIF, for looking at a recording.

A re-recorded GIF is reviewed by eye: did the banner scroll off, did the
pager page render, does the fix cast end on PASS. This pulls the frames
those questions are answered on — first, quarter, half, three-quarter, last
— as PNGs beside each GIF, so the review can be done anywhere an image can
be opened, by a person or by an agent that reads images. Needs Pillow,
which scripts/demo/requirements.lock pins.

Usage::

    frames.py docs/assets/demo.gif docs/assets/demo-fix.gif
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageSequence

PICKS = ("first", "quarter", "half", "three-quarter", "last")


def write_frames(gif: Path) -> list[Path]:
    """Save the five picked frames next to ``gif``; return their paths."""
    image = Image.open(gif)
    frames = [frame.convert("RGB") for frame in ImageSequence.Iterator(image)]
    count = len(frames)
    indexes = (0, count // 4, count // 2, 3 * count // 4, count - 1)
    written = []
    for label, index in zip(PICKS, indexes, strict=True):
        out = gif.with_name(f"{gif.stem}-{label}.png")
        frames[index].save(out)
        written.append(out)
    width, height = image.size
    print(f"{gif}: {width}x{height}, {count} frames -> {len(written)} PNGs")
    return written


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    for arg in argv:
        write_frames(Path(arg))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
