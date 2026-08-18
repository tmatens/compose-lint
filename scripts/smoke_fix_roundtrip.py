#!/usr/bin/env python3
"""End-to-end smoke for ``compose-lint fix`` — the one mode that writes.

``fix`` is covered by unit tests but was invoked by no workflow (#611).
That matters more here than for ``check``: a ``check`` bug prints
something wrong, a ``fix`` bug corrupts a file the user then commits.

``fix.verify_apply`` already re-runs the engine on the *candidate string*
before writing, so convergence and "no new finding" are enforced
in-process. What no test crossed is the boundary after that: the bytes
that reach disk, and whether anything other than compose-lint accepts
them. 0.20.0 shipped exactly one bug of that shape — the line-inserting
fixers spliced bare-LF lines into CRLF files, and the mixed-endings
result made every line of the user's next diff light up. Nothing in the
parsed tree is wrong in that file; only the bytes are.

So this closes the loop where a user stands:

1. copy the canonical insecure fixture to a scratch dir
2. ``fix --apply`` it
3. the result still parses as YAML, and ``docker compose config``
   accepts it — an external consumer, not our own mental model
4. line endings are still uniform and still the input's convention
5. re-lint: no finding appeared that was not there before, some finding
   went away, and ``fix`` offers nothing further (every claim it made is
   discharged)
6. a second ``--apply`` is byte-identical — idempotent

The whole loop runs twice, once on an LF copy and once on a CRLF copy,
because CRLF is a supported input shape with a known past failure.

Usage:
    python scripts/smoke_fix_roundtrip.py [--allow-missing-docker]

``docker compose config`` is required by default: a smoke that silently
drops its only external validator reads as "covered" when it is not. The
flag exists for local runs on hosts without Docker, and CI never passes
it.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
FIXTURE = REPO / "tests" / "smoke" / "insecure.yml"

failures: list[str] = []


def fail(variant: str, message: str) -> None:
    failures.append(f"[{variant}] {message}")
    print(f"::error::[{variant}] {message}")


def run(args: list[str], cwd: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True, timeout=120)


def lint(path: pathlib.Path) -> set[tuple[str, str]]:
    """Every finding as ``(rule_id, service)``, at the lowest threshold.

    ``--fail-on low`` keeps the comparison over the whole finding set
    rather than the gate's slice: a fix that traded a HIGH for a LOW
    would otherwise pass unnoticed.
    """
    proc = run(
        [
            sys.executable,
            "-m",
            "compose_lint",
            "check",
            "--fail-on",
            "low",
            "--format",
            "json",
            str(path.name),
        ],
        cwd=path.parent,
    )
    if proc.returncode not in (0, 1):
        raise SystemExit(
            f"check exited {proc.returncode} (expected 0 or 1)\n{proc.stderr}"
        )
    payload = json.loads(proc.stdout)
    return {(f["rule_id"], f["service"]) for f in payload["findings"]}


def newline_report(raw: bytes) -> tuple[int, int, int]:
    """``(lf_total, crlf, lone_cr)`` for a file's raw bytes."""
    lf_total = raw.count(b"\n")
    crlf = raw.count(b"\r\n")
    lone_cr = raw.count(b"\r") - crlf
    return lf_total, crlf, lone_cr


def check_endings(variant: str, raw: bytes, want_crlf: bool) -> None:
    lf_total, crlf, lone_cr = newline_report(raw)
    if lone_cr:
        fail(variant, f"{lone_cr} lone CR byte(s) in the fixed file")
    if want_crlf and crlf != lf_total:
        fail(
            variant,
            f"mixed line endings after fix: {crlf} CRLF vs {lf_total} total "
            "line breaks — inserted lines did not adopt the file's convention",
        )
    if not want_crlf and crlf:
        fail(variant, f"{crlf} CRLF ending(s) introduced into an LF file")


def smoke(variant: str, want_crlf: bool, require_docker: bool) -> None:
    print(f"\n=== fix round trip: {variant} ===")
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        target = work / "docker-compose.yml"
        # Normalise before building the variant. The repo has no
        # .gitattributes, so Git for Windows checks this fixture out with
        # CRLF under its default core.autocrlf=true — which made the "LF"
        # copy CRLF on the Windows leg, and the CRLF copy `\r\r\n`. Reading
        # the checkout verbatim would test the runner's git config rather
        # than compose-lint, in opposite directions per platform.
        source = FIXTURE.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        target.write_bytes(source.replace(b"\n", b"\r\n") if want_crlf else source)
        original = target.read_bytes()
        check_endings(f"{variant} (input)", original, want_crlf)
        if failures:
            raise SystemExit(
                "the scratch copy did not have the endings this variant is "
                "about to assert on — normalisation is broken, and the smoke "
                "would be testing the checkout rather than fix"
            )

        before = lint(target)
        if not before:
            raise SystemExit(
                "the insecure fixture produced no findings — the smoke would "
                "prove nothing; fixture and rules have drifted apart"
            )

        applied = run(
            [sys.executable, "-m", "compose_lint", "fix", "--apply", target.name],
            cwd=work,
        )
        print((applied.stdout + applied.stderr).strip() or "(no output)")
        if applied.returncode != 0:
            fail(variant, f"fix --apply exited {applied.returncode}\n{applied.stderr}")
            return

        fixed = target.read_bytes()
        if fixed == original:
            raise SystemExit(
                "fix --apply changed nothing on the canonical insecure fixture — "
                "the smoke would prove nothing; if a fixer was removed on "
                "purpose, point this script at a fixture that still has one"
            )

        # 3. Still Compose, judged by something that is not us.
        try:
            import yaml

            yaml.safe_load(fixed.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - any parse failure is the finding
            fail(variant, f"fixed file does not parse as YAML: {exc}")
            return

        if shutil.which("docker") is None:
            if require_docker:
                fail(
                    variant,
                    "docker is not available; `docker compose config` is this "
                    "smoke's only external validator. Pass "
                    "--allow-missing-docker to run the rest locally.",
                )
            else:
                print("::notice::docker absent — SKIPPED `docker compose config`")
        else:
            cfg = run(["docker", "compose", "-f", target.name, "config"], cwd=work)
            if cfg.returncode != 0:
                fail(
                    variant,
                    "`docker compose config` rejected the fixed file:\n"
                    f"{cfg.stderr.strip()}",
                )

        # 4. The bytes, not just the tree.
        check_endings(variant, fixed, want_crlf)

        # 5. Findings moved the right way.
        after = lint(target)
        introduced = after - before
        if introduced:
            fail(variant, f"fix introduced new finding(s): {sorted(introduced)}")
        if not (before - after):
            fail(
                variant, f"fix removed no finding (before == after == {sorted(after)})"
            )

        # Every claim discharged: a remaining auto-fixable finding would
        # still be offered here. Derived rather than a hardcoded rule
        # list, so a new fixer does not need this script updated.
        #
        # The *diff* is the signal, and it is on stdout — `fix` puts its
        # data there and its human summary on stderr (AGENTS.md), so an
        # empty stdout is exactly "nothing left to fix". Asserting on the
        # summary string instead would silently stop matching the day
        # that wording changes.
        residual = run(
            [sys.executable, "-m", "compose_lint", "fix", target.name], cwd=work
        )
        if residual.stdout.strip():
            fail(
                variant,
                "fix still offers changes after --apply:\n"
                f"{residual.stdout.strip()}\n{residual.stderr.strip()}",
            )

        # 6. Idempotent.
        again = run(
            [sys.executable, "-m", "compose_lint", "fix", "--apply", target.name],
            cwd=work,
        )
        if again.returncode != 0:
            fail(variant, f"second fix --apply exited {again.returncode}")
        elif target.read_bytes() != fixed:
            fail(variant, "second fix --apply changed the file again — not idempotent")

        print(
            f"[{variant}] removed {sorted(before - after)}; {len(after)} finding(s) remain"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-missing-docker",
        action="store_true",
        help="downgrade a missing docker to a skip (local runs only; CI must not)",
    )
    args = parser.parse_args()

    for variant, want_crlf in (("LF", False), ("CRLF", True)):
        smoke(variant, want_crlf, require_docker=not args.allow_missing_docker)

    if failures:
        print(f"\n{len(failures)} failure(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nfix round trip OK on both line-ending conventions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
