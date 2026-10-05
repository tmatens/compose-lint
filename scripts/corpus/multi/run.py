#!/usr/bin/env python3
"""Run Compose and one or more compose-lint builds over the multi-file corpus.

For each Compose project (a directory holding a primary compose file) under
``~/.cache/compose-lint-corpus-multi/repos``:

- **Compose's verdict**: ``docker compose config -q`` exit code, in a clean
  environment (PATH, an empty HOME and DOCKER_CONFIG) so nothing from this
  machine is interpolated. No ``-f``: an explicit file skips
  ``compose.override.*`` and ``COMPOSE_FILE``, which compose-lint honours, so
  discovery has to pick the same primary this script does. ``--reuse-compose``
  copies the verdicts from an earlier results file instead of re-running
  Compose, which is what a before/after comparison of two builds wants.
- **compose-lint**, one entry per ``--bin NAME=PATH``: run from the repository
  root with the file's relative path, the way CI runs it, in JSON. The exit
  code, diagnostic kinds, finding count, ``rule:service`` pairs and, for an
  exit 2, the error messages are recorded. Nothing a run prints reaches the
  terminal; stderr goes to a per-project log under the cache.

To compare a branch against ``main`` without installing either, point each
``--bin`` at a wrapper that sets ``PYTHONPATH`` to that checkout's ``src/``
before exec'ing ``python -m compose_lint`` — the environment handed to the
child is scrubbed, so the wrapper has to set it, and the main checkout's
``.venv/bin/compose-lint`` resolves to whatever branch that checkout is on.

Writes ``results.jsonl`` (``--out`` to choose) under the cache root. Prints
only counts. Read the results with ``analyze.py``.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path.home() / ".cache" / "compose-lint-corpus-multi"
REPOS = ROOT / "repos"
LOGS = ROOT / "logs"
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_BIN = REPO_ROOT / ".venv" / "bin" / "compose-lint"
PRIMARY = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv"}


def projects(repo: Path) -> list[Path]:
    """Every primary compose file under ``repo``, by Compose's name precedence."""
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(repo):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in PRIMARY:
            if name in filenames:
                found.append(Path(dirpath) / name)
                break
    return found


def clean_env(home: str) -> dict[str, str]:
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": home,
        "DOCKER_CONFIG": home,
        "NO_COLOR": "1",
        "LANG": "C.UTF-8",
    }


def compose_verdict(primary: Path, log: Path, env: dict[str, str]) -> int | str:
    try:
        proc = subprocess.run(
            ["docker", "compose", "config", "-q"],
            cwd=primary.parent,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return "timeout"
    log.with_suffix(".compose.err").write_text(proc.stderr)
    return proc.returncode


def lint(binary: Path, repo: Path, rel: Path, log: Path, env: dict[str, str]) -> dict:
    try:
        proc = subprocess.run(
            [str(binary), "--format", "json", "--", str(rel)],
            cwd=repo,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return {"rc": "timeout"}
    entry: dict = {"rc": proc.returncode}
    try:
        doc = json.loads(proc.stdout)
        errors = doc.get("errors", [])
        entry["errors"] = sorted({e["kind"] for e in errors})
        entry["warnings"] = sorted({w["kind"] for w in doc.get("warnings", [])})
        findings = doc.get("findings", [])
        entry["n"] = len(findings)
        entry["rules"] = sorted(f"{f['rule_id']}:{f.get('service')}" for f in findings)
        if proc.returncode == 2:
            entry["messages"] = [e["message"][:300] for e in errors][:8]
    except (json.JSONDecodeError, AttributeError, TypeError, KeyError):
        entry["unparsed"] = True
        entry["messages"] = [proc.stderr.strip()[-300:]]
    log.with_suffix(f".{binary.name}.err").write_text(proc.stderr)
    return entry


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--bin",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help=f"a compose-lint build to run (default: main={DEFAULT_BIN})",
    )
    parser.add_argument(
        "--reuse-compose",
        metavar="RESULTS",
        help="copy Compose's verdicts from this results file instead of running it",
    )
    parser.add_argument("--out", default=str(ROOT / "results.jsonl"))
    parser.add_argument(
        "--limit", type=int, help="only the first N projects (a smoke run)"
    )
    parser.add_argument(
        "--workers", type=int, default=int(os.environ.get("WORKERS", "8"))
    )
    args = parser.parse_args()

    bins: dict[str, Path] = {}
    for spec in args.bin or [f"main={DEFAULT_BIN}"]:
        name, _, path = spec.partition("=")
        if not path:
            parser.error(f"--bin wants NAME=PATH, got {spec!r}")
        bins[name] = Path(path).expanduser()
    reused: dict[str, int | str] = {}
    if args.reuse_compose:
        with open(args.reuse_compose, encoding="utf-8") as handle:
            for line in handle:
                row = json.loads(line)
                reused[row["project"]] = row.get("compose_rc")

    LOGS.mkdir(parents=True, exist_ok=True)
    repos = sorted(p for p in REPOS.iterdir() if p.is_dir())
    work = [p for repo in repos for p in projects(repo)]
    if args.limit:
        work = work[: args.limit]
    print(f"{len(work)} projects in {len(repos)} repos", file=sys.stderr)

    def run_one(primary: Path) -> dict:
        repo = next(p for p in primary.parents if p.parent == REPOS)
        rel = primary.relative_to(repo)
        key = f"{repo.name}/{rel}"
        log = LOGS / key.replace("/", "__")
        result: dict = {"project": key}
        with tempfile.TemporaryDirectory() as home:
            env = clean_env(home)
            if key in reused:
                result["compose_rc"] = reused[key]
            else:
                result["compose_rc"] = compose_verdict(primary, log, env)
            for name, binary in bins.items():
                result[name] = lint(binary, repo, rel, log, env)
        return result

    with ThreadPoolExecutor(args.workers) as pool:
        results = list(pool.map(run_one, work))
    with open(args.out, "w", encoding="utf-8") as out:
        for row in results:
            out.write(json.dumps(row) + "\n")
    print(f"wrote {len(results)} results to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
