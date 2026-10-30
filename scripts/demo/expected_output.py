#!/usr/bin/env python3
"""Print, write or check the terminal text the README demo casts show.

The two tapes in this directory type a fixed set of commands at a released
compose-lint. This script runs the same commands at whichever compose-lint it
is pointed at and prints what they produce, with the version banner masked,
so two releases can be compared on what the GIFs would *show* rather than on
which version rendered them.

``expected-output.txt`` beside this file is the text the committed GIFs were
recorded from. It is written only by this script's ``--write``, as part of a
re-record, never by hand: it records what the GIFs show, not what the source
tree would print today. (A test that held it to the working tree would update
it before a release and leave the re-record job with nothing to notice.)

The hero cast's ``--explain`` page is deliberately not part of the text: it
is a rule's documentation page, which moves with every wording edit, and a
re-record for each of those would be noise. What is compared is the lint and
fix output, the part a release can change.

Usage::

    expected_output.py [--compose-lint PATH]            # print
    expected_output.py --write expected-output.txt      # record
    expected_output.py --check expected-output.txt      # exit 1 on a diff
"""

from __future__ import annotations

import argparse
import difflib
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent

# The banner is the only place the text spells `compose-lint X.Y.Z`; it may
# sit inside colour codes, so the match is not anchored to the line.
_BANNER = re.compile(r"compose-lint \d+\.\d+\.\d+")


def mask(text: str) -> str:
    """Replace the version in the ``compose-lint X.Y.Z`` banner."""
    return _BANNER.sub("compose-lint <version>", text)


# Rows the hero tape's terminal shows at its font and height, per the comment
# above `Set Height` in demo.tape. The lint step must fit in them: the typed
# command, every output line, and the prompt that follows. A `check` that
# gained a line (0.36.1 added the --explain hint) pushes the banner off the
# top of the recording, which nothing but eyes caught before this.
HERO_ROWS = 32


def hero_rows_needed(text: str) -> int:
    """Rows the hero cast's lint step takes: command + output + prompt."""
    section = text.split("=== ", 2)[1].rstrip("\n")  # the hero check comes first
    lines = section.splitlines()[1:]  # drop the "demo.tape: ..." title
    output = [ln for ln in lines if not ln.startswith("[exit ")]
    return 1 + len(output) + 1


def _run(binary: str, args: list[str], cwd: pathlib.Path) -> str:
    proc = subprocess.run(  # noqa: S603 - the binary is the caller's choice
        [binary, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        # Colour is forced so that a change to how the text is coloured
        # counts as a change to what the GIF shows; TERM=dumb keeps the
        # pager out of it (the --explain page is not compared).
        env={
            "PATH": "/usr/bin:/bin",
            "FORCE_COLOR": "1",
            "TERM": "dumb",
            "HOME": str(cwd),
        },
    )
    return proc.stdout + proc.stderr + f"[exit {proc.returncode}]\n"


def render(binary: str) -> str:
    """The text both casts produce, in cast order, banners masked."""
    sections: list[tuple[str, str]] = []
    # Hero cast (demo.tape): `check` on the two-service fixture.
    hero = _run(binary, ["docker-compose.yml"], HERE)
    sections.append(("demo.tape: compose-lint docker-compose.yml", hero))
    # Fix cast (fix.tape): dry run, apply, re-lint — on a copy, since --apply
    # rewrites the file, exactly as the tape copies it to /tmp first.
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        shutil.copy(HERE / "fix-compose.yml", work / "fix-compose.yml")
        for title, args in (
            ("fix.tape: compose-lint fix fix-compose.yml", ["fix", "fix-compose.yml"]),
            (
                "fix.tape: compose-lint fix --apply fix-compose.yml",
                ["fix", "--apply", "fix-compose.yml"],
            ),
            ("fix.tape: compose-lint fix-compose.yml", ["fix-compose.yml"]),
        ):
            sections.append((title, _run(binary, args, work)))
    out = []
    for title, text in sections:
        out.append(f"=== {title}\n{text}")
    return mask("\n".join(out))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--compose-lint",
        default="compose-lint",
        help="compose-lint executable to run (default: the one on PATH)",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--write", type=pathlib.Path, help="record the text to FILE")
    group.add_argument(
        "--check", type=pathlib.Path, help="compare against FILE; exit 1 on a diff"
    )
    args = parser.parse_args(argv)

    binary = shutil.which(args.compose_lint) or args.compose_lint
    text = render(binary)
    needed = hero_rows_needed(text)
    if needed > HERO_ROWS:
        print(
            f"::error::the hero cast's lint step needs {needed} rows but demo.tape's "
            f"terminal shows {HERO_ROWS}; the banner would scroll off. Raise "
            "`Set Height` in scripts/demo/demo.tape (and HERO_ROWS here) first.",
            file=sys.stderr,
        )
        return 2
    if args.write:
        args.write.write_text(text, encoding="utf-8")
        print(f"wrote {args.write}")
        return 0
    if args.check:
        expected = args.check.read_text(encoding="utf-8")
        if expected == text:
            print("demo output unchanged")
            return 0
        sys.stdout.writelines(
            difflib.unified_diff(
                expected.splitlines(keepends=True),
                text.splitlines(keepends=True),
                fromfile=str(args.check),
                tofile="current",
            )
        )
        return 1
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
