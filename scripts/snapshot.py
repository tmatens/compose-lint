#!/usr/bin/env python3
"""Corpus regression snapshot tool.

Reads compose-lint output from a corpus run (produced by external
`fetch.py` + `run.py` against ~/.cache/compose-lint-corpus/) and emits or
diffs a normalised digest committed at tests/corpus_snapshot.json.gz.

The digest stores only (rule_id, service, line) tuples keyed by file
content hash. No file paths, finding messages, or third-party content
lands in the snapshot. See LICENSE-corpus.md for the licensing posture.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SNAPSHOT = REPO_ROOT / "tests" / "corpus_snapshot.json.gz"
DEFAULT_CACHE = Path.home() / ".cache" / "compose-lint-corpus"


def _latest_run_dir(cache: Path) -> Path:
    runs = cache / "runs"
    if not runs.is_dir():
        raise SystemExit(f"no runs dir at {runs}")
    candidates = sorted(p for p in runs.iterdir() if p.is_dir())
    if not candidates:
        raise SystemExit(f"no run subdirectories under {runs}")
    return candidates[-1]


def _manifest_hash(index_path: Path) -> str:
    return hashlib.sha256(index_path.read_bytes()).hexdigest()


def _load_findings(results_path: Path) -> tuple[dict[str, list[list[Any]]], list[str]]:
    findings: dict[str, list[list[Any]]] = {}
    parse_errors: list[str] = []
    with results_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            content_hash = entry["content_hash"]
            if entry.get("error") == "usage_or_parse":
                parse_errors.append(content_hash)
                continue
            tuples: list[list[Any]] = []
            for f in entry.get("lint", []):
                tuples.append([f["rule_id"], f.get("service") or "", f.get("line")])
            tuples.sort(key=lambda t: (t[0], t[1], t[2] if t[2] is not None else -1))
            if tuples:
                findings[content_hash] = tuples
    parse_errors.sort()
    return findings, parse_errors


def _load_run_meta(run_dir: Path) -> dict[str, Any]:
    meta_path = run_dir / "meta.json"
    if not meta_path.is_file():
        raise SystemExit(f"no meta.json at {meta_path}")
    return json.loads(meta_path.read_text(encoding="utf-8"))


def build_digest(run_dir: Path, index_path: Path) -> dict[str, Any]:
    meta = _load_run_meta(run_dir)
    findings, parse_errors = _load_findings(run_dir / "results.jsonl")
    return {
        "schema_version": SCHEMA_VERSION,
        "corpus_manifest_sha256": _manifest_hash(index_path),
        "compose_lint_version": meta["compose_lint_version"],
        "files_processed": meta["files_processed"],
        "findings": findings,
        "parse_errors": parse_errors,
    }


def write_snapshot(snapshot_path: Path, digest: dict[str, Any]) -> None:
    payload = json.dumps(digest, indent=2, sort_keys=True).encode("utf-8")
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    with (
        snapshot_path.open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=9, mtime=0) as fh,
    ):
        fh.write(payload)


def read_snapshot(snapshot_path: Path) -> dict[str, Any]:
    with gzip.open(snapshot_path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def diff_digests(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    """Return human-readable diff lines; empty list = identical findings."""
    out: list[str] = []
    if expected.get("compose_lint_version") != actual.get("compose_lint_version"):
        out.append(
            f"compose_lint_version: expected "
            f"{expected.get('compose_lint_version')}, got "
            f"{actual.get('compose_lint_version')}"
        )
    if expected.get("corpus_manifest_sha256") != actual.get("corpus_manifest_sha256"):
        out.append(
            "corpus_manifest_sha256 differs (corpus refreshed without snapshot regen)"
        )

    exp_f = expected.get("findings", {})
    act_f = actual.get("findings", {})
    all_hashes = sorted(set(exp_f) | set(act_f))
    for h in all_hashes:
        exp_tuples = {tuple(t) for t in exp_f.get(h, [])}
        act_tuples = {tuple(t) for t in act_f.get(h, [])}
        added = sorted(act_tuples - exp_tuples)
        removed = sorted(exp_tuples - act_tuples)
        if added or removed:
            out.append(f"file {h}:")
            for t in removed:
                out.append(f"  - {t[0]} {t[1]}:{t[2]}")
            for t in added:
                out.append(f"  + {t[0]} {t[1]}:{t[2]}")

    exp_e = set(expected.get("parse_errors", []))
    act_e = set(actual.get("parse_errors", []))
    for h in sorted(act_e - exp_e):
        out.append(f"new parse error: {h}")
    for h in sorted(exp_e - act_e):
        out.append(f"resolved parse error: {h}")
    return out


def _resolve_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    cache = Path(args.cache).expanduser() if args.cache else DEFAULT_CACHE
    run_dir = (
        Path(args.run_dir).expanduser() if args.run_dir else _latest_run_dir(cache)
    )
    index_path = Path(args.index).expanduser() if args.index else cache / "index.jsonl"
    if not run_dir.is_dir():
        raise SystemExit(f"run-dir not found: {run_dir}")
    if not index_path.is_file():
        raise SystemExit(f"index not found: {index_path}")
    return run_dir, index_path


def cmd_generate(args: argparse.Namespace) -> int:
    run_dir, index_path = _resolve_paths(args)
    digest = build_digest(run_dir, index_path)
    snapshot_path = Path(args.snapshot).expanduser()
    write_snapshot(snapshot_path, digest)
    print(
        f"wrote {snapshot_path} ({len(digest['findings'])} files, "
        f"{sum(len(v) for v in digest['findings'].values())} findings, "
        f"{len(digest['parse_errors'])} parse errors)"
    )
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    run_dir, index_path = _resolve_paths(args)
    expected = read_snapshot(Path(args.snapshot).expanduser())
    actual = build_digest(run_dir, index_path)
    diff = diff_digests(expected, actual)
    if not diff:
        print("snapshot matches current run")
        return 0
    print("\n".join(diff))
    return 1


def cmd_verify(args: argparse.Namespace) -> int:
    return cmd_diff(args)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    common_args = [
        ("--cache", "Corpus cache root (default: ~/.cache/compose-lint-corpus)"),
        ("--run-dir", "Run dir (default: latest under <cache>/runs/)"),
        ("--index", "index.jsonl path (default: <cache>/index.jsonl)"),
        ("--snapshot", f"Snapshot path (default: {DEFAULT_SNAPSHOT})"),
    ]

    subcommands = (
        ("generate", cmd_generate),
        ("diff", cmd_diff),
        ("verify", cmd_verify),
    )
    for cmd_name, fn in subcommands:
        p = sub.add_parser(cmd_name)
        for flag, help_text in common_args:
            p.add_argument(flag, help=help_text, default=None)
        p.set_defaults(func=fn)

    args = parser.parse_args(argv)
    if args.snapshot is None:
        args.snapshot = str(DEFAULT_SNAPSHOT)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
