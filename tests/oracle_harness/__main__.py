"""Replay one seed: write its project out and print both answers.

A generated failure is only useful if it can be looked at. The assertion
message names the seed and this command; this command turns the seed back into
files.

    python -m tests.oracle_harness --seed 731
    python -m tests.oracle_harness --seed 731 --keep /tmp/seed731
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from tests.oracle_harness._compare import (
    describe_difference,
    lint_project,
    truth_findings,
)
from tests.oracle_harness._oracle import oracle_available, oracle_version, run_oracle
from tests.oracle_harness._project import generate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tests.oracle_harness")
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument(
        "--keep",
        type=Path,
        help="write the project here and leave it (default: a temp dir, removed)",
    )
    args = parser.parse_args(argv)

    project = generate(args.seed)
    print(project.render())

    if not oracle_available():
        print("\nno docker compose CLI on PATH; generated the project only")
        return 0

    with tempfile.TemporaryDirectory() as temporary:
        root = args.keep if args.keep is not None else Path(temporary) / "project"
        root.mkdir(parents=True, exist_ok=True)
        primary = project.write(root)
        print(f"\nproject: {root}")
        print(f"oracle:  Compose {oracle_version()}")

        oracle = run_oracle(root)
        linted = lint_project(primary)

        print(f"\ncompose exit {oracle.returncode}")
        if oracle.stderr.strip():
            print(oracle.stderr.strip())
        if linted.error is not None:
            print(f"\ncompose-lint refused: {linted.error}")
            return 0
        if linted.gaps:
            print("\ncompose-lint coverage gaps:")
            for gap in linted.gaps:
                print(f"  {gap}")
            return 0
        if not oracle.accepted:
            return 0

        expected = truth_findings(oracle.stdout, Path(temporary) / "truth")
        print("\nfindings")
        print(f"  ours:   {sorted(linted.findings.elements())}")
        print(f"  theirs: {sorted(expected.elements())}")
        if linted.findings != expected:
            print(describe_difference(linted.findings, expected))
    return 0


if __name__ == "__main__":  # pragma: no cover - developer entry point
    sys.exit(main())
