#!/usr/bin/env python3
"""External-validity gate — does Docker still accept a file after we fix it?

The fix_gate (and the committed ``tests/test_corpus_fix.py``) prove the
*internal* ADR-014 invariants: patched text re-parses with our own parser, is
idempotent, and adds no new finding. This gate proves the *external* one: that
``docker compose config`` — Docker's own loader/interpolator — still accepts the
file after ``compose-lint fix --apply``.

It is differential. Many real corpus files fail ``docker compose config`` on
their own (missing ``include:`` targets, env-only required values, etc.), and
that is not our fault. So a file is only a REGRESSION when Docker accepted the
*original* but rejects the *fixed* version. To keep the run cheap we validate the
fixed file first and only fall back to validating the original when the fixed one
fails — the common case (fix is fine) costs a single ``config`` invocation.

Requires the Docker Compose CLI plugin (``docker compose version``). If it is
absent the gate SKIPs with exit 0 so it never breaks a Docker-less CI leg.

    python scripts/corpus/docker_config_gate.py            # all cores, full corpus
    python scripts/corpus/docker_config_gate.py --limit 300  # quick sample
    LINT_WORKERS=4 python scripts/corpus/docker_config_gate.py

Corpus lives outside the repo at ~/.cache/compose-lint-corpus/files/ (see
README.md). Exits non-zero if any fix regresses Docker acceptance.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from multiprocessing import Pool
from pathlib import Path

from compose_lint.engine import run_rules
from compose_lint.fix import apply_edits, collect_edits
from compose_lint.parser import (
    ComposeError,
    ComposeNotApplicableError,
    load_compose,
)

CACHE = Path.home() / ".cache" / "compose-lint-corpus"
FILES = CACHE / "files"
WORKERS = int(os.environ.get("LINT_WORKERS", str(os.cpu_count() or 4)))
# config is pure parse + interpolation, but guard against a pathological hang.
CONFIG_TIMEOUT = 30


def _docker_config_ok(text: str) -> tuple[bool, str]:
    """Write ``text`` to an isolated project dir and run ``docker compose config``.

    Returns ``(accepted, stderr)``. Each file gets its own temp dir so Docker's
    env-file / project-name resolution can't leak between files or pick up a
    stray ``.env`` from the shared cwd.
    """
    with tempfile.TemporaryDirectory() as project:
        compose = Path(project) / "compose.yaml"
        compose.write_text(text, encoding="utf-8")
        try:
            proc = subprocess.run(
                ["docker", "compose", "-f", str(compose), "config", "-q"],
                capture_output=True,
                text=True,
                timeout=CONFIG_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return False, f"timeout after {CONFIG_TIMEOUT}s"
        return proc.returncode == 0, proc.stderr.strip()


def check_file(path: Path) -> dict:
    """Validate one file's fix against ``docker compose config``."""
    result: dict = {
        "fixed": 0,
        "fixed_ok": 0,
        "regression": None,
        "preexisting": 0,
    }
    try:
        data, lines = load_compose(path)
    except (ComposeError, ComposeNotApplicableError, FileNotFoundError):
        return result
    text = path.read_text(encoding="utf-8")
    findings = run_rules(data, lines)
    collected = collect_edits(findings, data, lines, text)
    if not collected.edits:
        return result
    result["fixed"] = 1
    patched = apply_edits(text, collected.edits)

    fixed_ok, fixed_err = _docker_config_ok(patched)
    if fixed_ok:
        result["fixed_ok"] = 1
        return result

    # Fixed text was rejected — was the original accepted? If so, we broke it.
    orig_ok, _ = _docker_config_ok(text)
    if orig_ok:
        reason = fixed_err.splitlines()[-1] if fixed_err else "rejected"
        result["regression"] = f"{path.name}: {reason}"
    else:
        result["preexisting"] = 1
    return result


def _plugin_available() -> bool:
    try:
        proc = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="validate only the first N corpus files (0 = all)",
    )
    args = parser.parse_args()

    if not _plugin_available():
        print(
            "SKIP: 'docker compose' plugin not available; "
            "install it to run the external-validity gate.",
            file=sys.stderr,
        )
        return 0

    files = sorted(FILES.glob("*.yml"))
    if not files:
        print(f"no corpus files under {FILES}", file=sys.stderr)
        return 2
    if args.limit:
        files = files[: args.limit]
    print(f"corpus files: {len(files)} · workers: {WORKERS}", file=sys.stderr)

    fixed = fixed_ok = preexisting = 0
    regressions: list[str] = []

    started = time.monotonic()
    with Pool(processes=WORKERS) as pool:
        for record in pool.imap_unordered(check_file, files, chunksize=8):
            fixed += record["fixed"]
            fixed_ok += record["fixed_ok"]
            preexisting += record["preexisting"]
            if record["regression"]:
                regressions.append(record["regression"])
    elapsed = time.monotonic() - started

    print(f"files with fixes: {fixed}  ({elapsed:.0f}s)")
    print(f"  docker accepts fixed file:        {fixed_ok}")
    print(f"  docker rejected orig AND fixed:   {preexisting}  (pre-existing)")
    print(f"  REGRESSIONS (orig ok, fixed bad): {len(regressions)}")
    for item in regressions[:25]:
        print(f"    {item}")

    if regressions:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
