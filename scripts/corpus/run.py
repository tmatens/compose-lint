#!/usr/bin/env python3
"""Run compose-lint over every file in the corpus, write per-file JSONL + summary.md.

Output goes to ~/.cache/compose-lint-corpus/runs/<timestamp>/:
  results.jsonl   - one line per file with full lint output
  errors.jsonl    - parse errors / crashes (separate so they don't pollute findings)
  summary.md      - human-readable aggregate (rule counts, severity dist, top examples)
  meta.json       - run params (compose-lint version, file count, timing)

Designed to be referenceable from a future Claude session: stable layout, jq-friendly JSONL.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

CACHE = Path.home() / ".cache" / "compose-lint-corpus"
FILES = CACHE / "files"
INDEX = CACHE / "index.jsonl"
RUNS = CACHE / "runs"

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_LINT = os.environ.get(
    "COMPOSE_LINT_BIN",
    str(REPO_ROOT / ".venv" / "bin" / "compose-lint"),
)
PER_FILE_TIMEOUT = 30
WORKERS = int(os.environ.get("LINT_WORKERS", "8"))
GLOBAL_TIMEOUT_SECS = int(os.environ.get("LINT_TIMEOUT", "1500"))  # 25 min

# Severity weights for impact column. Doubling per step keeps a single
# CRITICAL finding visible against a flood of MEDIUMs while still letting
# very common HIGHs surface. Documented in the State of Compose report's
# methodology section so readers can re-rank with a different curve.
SEVERITY_WEIGHT = {"critical": 8, "high": 4, "medium": 2, "low": 1}


def _fmt_weights() -> str:
    return ", ".join(f"{k}={v}" for k, v in SEVERITY_WEIGHT.items())


# Order matters: first matching pattern wins. Tested against
# runs/20260503T034026Z (178 parse errors, 15 distinct first-line
# fingerprints) — these patterns cover every observed class.
_PARSE_ERROR_CLASSES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("missing-services-key",   re.compile(r"missing 'services' key")),
    ("services-not-mapping",   re.compile(r"'services' must be a mapping")),
    ("service-not-mapping",    re.compile(r"service '[^']+' must be a mapping")),
    ("empty-file",             re.compile(r"file is empty")),
    ("top-level-not-mapping",  re.compile(r"expected a YAML mapping at the top level")),
    ("invalid-yaml",           re.compile(r"Invalid YAML:")),
)


def classify_parse_error(stderr: str | None) -> str:
    """Bucket a compose-lint exit-2 stderr into a stable class label.

    Class labels are stable across runs so the State of Compose report
    can quote them. Anything unmatched falls into `other` so a new
    failure mode is visible rather than silently merged with a known one.
    """
    if not stderr:
        return "other"
    first = stderr.splitlines()[0]
    for label, pat in _PARSE_ERROR_CLASSES:
        if pat.search(first):
            return label
    return "other"


_PARSE_CLASS_ORDER = (
    "missing-services-key",
    "services-not-mapping",
    "service-not-mapping",
    "top-level-not-mapping",
    "empty-file",
    "invalid-yaml",
    "other",
)


def lint_one(path_str: str) -> dict:
    path = Path(path_str)
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            [COMPOSE_LINT, "--format", "json", "--fail-on", "low", str(path)],
            capture_output=True, text=True, timeout=PER_FILE_TIMEOUT,
        )
        elapsed = time.monotonic() - t0
        result: dict = {
            "content_hash": path.stem,
            "exit_code": proc.returncode,
            "elapsed_ms": int(elapsed * 1000),
        }
        # exit 0/1 → JSON on stdout; exit 2 → usage/parse error on stderr
        if proc.returncode in (0, 1):
            try:
                result["lint"] = json.loads(proc.stdout) if proc.stdout.strip() else None
            except json.JSONDecodeError as e:
                result["error"] = f"json_decode: {e}"
                result["stdout_head"] = proc.stdout[:500]
        else:
            result["error"] = "usage_or_parse"
            result["stderr"] = proc.stderr.strip()[:1000]
        return result
    except subprocess.TimeoutExpired:
        return {"content_hash": path.stem, "error": "timeout", "elapsed_ms": PER_FILE_TIMEOUT * 1000}
    except Exception as e:
        return {"content_hash": path.stem, "error": f"{type(e).__name__}: {e}"}


def load_index() -> dict[str, dict]:
    out: dict[str, dict] = {}
    if not INDEX.exists():
        return out
    with INDEX.open() as f:
        for line in f:
            try:
                rec = json.loads(line)
                out[rec["content_hash"]] = rec
            except Exception:
                continue
    return out


def summarize(run_dir: Path, results: list[dict], index: dict[str, dict], started_at: str, elapsed: float) -> None:
    total = len(results)
    parse_errors = [r for r in results if r.get("error") == "usage_or_parse"]
    timeouts = [r for r in results if r.get("error") == "timeout"]
    crashes = [r for r in results if r.get("error") and r["error"] not in ("usage_or_parse", "timeout")]
    linted = [r for r in results if r.get("lint") is not None]

    rule_counts: Counter[str] = Counter()
    rule_severity: dict[str, str] = {}
    severity_counts: Counter[str] = Counter()
    rule_examples: dict[str, list[tuple[str, str, int]]] = defaultdict(list)  # rule_id -> [(repo, path, line)]
    findings_per_file: list[int] = []
    files_with_findings = 0
    files_clean = 0

    for r in linted:
        lint = r["lint"]
        findings = lint if isinstance(lint, list) else lint.get("findings", [])
        findings_per_file.append(len(findings))
        if findings:
            files_with_findings += 1
        else:
            files_clean += 1
        for f in findings:
            rid = f.get("rule_id", "?")
            sev = (f.get("severity") or "?").lower()
            rule_counts[rid] += 1
            severity_counts[sev] += 1
            # First-seen severity per rule. Rules have a fixed severity
            # in compose-lint, so any finding suffices.
            if rid not in rule_severity:
                rule_severity[rid] = sev
            if len(rule_examples[rid]) < 3:
                meta = index.get(r["content_hash"], {})
                rule_examples[rid].append((
                    meta.get("repo", "?"),
                    meta.get("path", "?"),
                    f.get("line") or f.get("line_number") or 0,
                ))

    avg_findings = sum(findings_per_file) / len(findings_per_file) if findings_per_file else 0
    median_findings = sorted(findings_per_file)[len(findings_per_file) // 2] if findings_per_file else 0

    lines = [
        f"# compose-lint corpus run — {started_at}",
        "",
        f"- Corpus location: `{FILES}`",
        f"- Run directory: `{run_dir}`",
        f"- Tool: `{COMPOSE_LINT}` (compose-lint {get_cl_version()})",
        f"- Wall time: {elapsed:.1f}s",
        "",
        "## Counts",
        "",
        f"- Total files: **{total}**",
        f"- Successfully linted: **{len(linted)}**",
        f"  - Files with findings: {files_with_findings}",
        f"  - Files clean: {files_clean}",
        f"- Parse / usage errors (exit 2): **{len(parse_errors)}**",
        f"- Timeouts (>{PER_FILE_TIMEOUT}s): **{len(timeouts)}**",
        f"- Crashes / other: **{len(crashes)}**",
        "",
        f"- Findings per file: avg {avg_findings:.2f}, median {median_findings}, max {max(findings_per_file or [0])}",
        "",
        "## Severity distribution",
        "",
    ]
    for sev in ("critical", "high", "medium", "low"):
        lines.append(f"- {sev}: {severity_counts.get(sev, 0)}")
    lines += [
        "",
        "## Rule hit counts (descending)",
        "",
        f"`Impact` = severity weight × files-affected. Weights: {_fmt_weights()}.",
        "",
    ]
    if rule_counts:
        lines.append("| Rule | Severity | Hits | Files | Impact | Example |")
        lines.append("| --- | --- | ---: | ---: | ---: | --- |")
        # files-affected per rule
        files_per_rule: Counter[str] = Counter()
        for r in linted:
            seen = set()
            lint = r["lint"]
            findings = lint if isinstance(lint, list) else lint.get("findings", [])
            for f in findings:
                rid = f.get("rule_id", "?")
                if rid not in seen:
                    files_per_rule[rid] += 1
                    seen.add(rid)
        for rid, n in rule_counts.most_common():
            sev = rule_severity.get(rid, "?")
            impact = SEVERITY_WEIGHT.get(sev, 0) * files_per_rule[rid]
            ex = rule_examples.get(rid, [])
            ex_str = ", ".join(f"{repo}#{path}:{line}" for repo, path, line in ex[:1])
            lines.append(f"| `{rid}` | {sev} | {n} | {files_per_rule[rid]} | {impact} | {ex_str} |")
    else:
        lines.append("_No findings._")

    if parse_errors:
        parse_class_counts: Counter[str] = Counter(
            classify_parse_error(r.get("stderr")) for r in parse_errors
        )
        lines += [
            "",
            "## Parse-error classes",
            "",
            (
                "Every exit-2 result bucketed by stderr class. Treat the"
                + " parse-error population as a finding (the report cites it),"
                + " not a discard."
            ),
            "",
            "| Class | Count |",
            "| --- | ---: |",
        ]
        for cls in _PARSE_CLASS_ORDER:
            n = parse_class_counts.get(cls, 0)
            if n:
                lines.append(f"| `{cls}` | {n} |")

    lines += ["", "## Parse errors (sample of first 10)", ""]
    for r in parse_errors[:10]:
        meta = index.get(r["content_hash"], {})
        msg = (r.get("stderr") or "").splitlines()[0] if r.get("stderr") else ""
        lines.append(f"- `{meta.get('repo','?')}` / `{meta.get('path','?')}` — {msg[:200]}")

    if crashes:
        lines += ["", "## Crashes / unexpected errors", ""]
        for r in crashes[:20]:
            meta = index.get(r["content_hash"], {})
            lines.append(f"- `{meta.get('repo','?')}` / `{meta.get('path','?')}` — {r.get('error')}")

    lines += [
        "",
        "## Result schema",
        "",
        "Each line in `results.jsonl` is one of:",
        "- successful lint: `{content_hash, exit_code, elapsed_ms, lint: [<finding>, ...]}`",
        "  (`lint` is the raw compose-lint JSON array — empty array means clean)",
        "- parse / usage error: `{content_hash, error: \"usage_or_parse\", stderr}`",
        "- timeout / crash: `{content_hash, error: \"timeout\" | \"<ExceptionName>\"}`",
        "",
        "Each line in `~/.cache/compose-lint-corpus/index.jsonl` is the source mapping:",
        "`{content_hash, blob_sha, repo, path, url, size}`.",
        "",
        "## How to query results in a future session",
        "",
        "```bash",
        f"RUN={run_dir}",
        f"IDX={INDEX}",
        "",
        "# all findings for rule CL-0001",
        "jq -c '.lint[]? | select(.rule_id==\"CL-0001\")' $RUN/results.jsonl",
        "",
        "# files where compose-lint exited 2 (parse / usage error)",
        "jq -c 'select(.error==\"usage_or_parse\") | {hash: .content_hash, err: .stderr}' \\",
        "  $RUN/results.jsonl",
        "",
        "# top 20 files by finding count, with source repo",
        "jq -c 'select(.lint) | {h: .content_hash, n: (.lint | length)}' $RUN/results.jsonl \\",
        "  | jq -s 'sort_by(-.n) | .[0:20]' \\",
        "  | jq -c '.[]' \\",
        "  | while read row; do h=$(jq -r .h <<<\"$row\"); n=$(jq -r .n <<<\"$row\"); \\",
        "      src=$(jq -c \"select(.content_hash==\\\"$h\\\") | {repo,path}\" $IDX); \\",
        "      echo \"$n $src\"; done",
        "",
        "# read the actual compose file for a finding",
        "cat ~/.cache/compose-lint-corpus/files/<content_hash>.yml",
        "```",
    ]

    (run_dir / "summary.md").write_text("\n".join(lines))


def summarize_tiers(run_dir: Path, results: list[dict], index: dict[str, dict]) -> None:
    """Write tier_summary.md: per-tier counts, severity dist, top rules.

    Joins results.jsonl entries to index entries by content_hash and groups
    by `tier`. Untagged entries fall into 'unknown' so missing index rows
    are visible rather than silently dropped.
    """
    by_tier: dict[str, dict] = defaultdict(lambda: {
        "total": 0, "parsed": 0, "parse_errors": 0, "timeouts": 0,
        "clean": 0, "with_findings": 0, "findings": 0,
        "rules": Counter(), "severity": Counter(),
        "files_per_rule": Counter(),  # rule_id -> distinct files in this tier
        "parse_classes": Counter(),  # exit-2 stderr class -> count in this tier
    })
    rule_severity: dict[str, str] = {}

    for r in results:
        tier = index.get(r["content_hash"], {}).get("tier", "unknown")
        b = by_tier[tier]
        b["total"] += 1
        if r.get("error") == "usage_or_parse":
            b["parse_errors"] += 1
            b["parse_classes"][classify_parse_error(r.get("stderr"))] += 1
            continue
        if r.get("error") == "timeout":
            b["timeouts"] += 1
            continue
        if r.get("lint") is None:
            continue  # other crash; counted in 'total' only
        b["parsed"] += 1
        lint = r["lint"]
        findings = lint if isinstance(lint, list) else lint.get("findings", [])
        if findings:
            b["with_findings"] += 1
        else:
            b["clean"] += 1
        seen_in_file: set[str] = set()
        for f in findings:
            rid = f.get("rule_id", "?")
            sev = (f.get("severity") or "?").lower()
            b["findings"] += 1
            b["rules"][rid] += 1
            b["severity"][sev] += 1
            if rid not in rule_severity:
                rule_severity[rid] = sev
            if rid not in seen_in_file:
                b["files_per_rule"][rid] += 1
                seen_in_file.add(rid)

    lines = [
        f"# compose-lint per-tier summary — {run_dir.name}",
        "",
        "Joined `results.jsonl` × `index.jsonl` on `content_hash`, grouped by `tier`.",
        "",
        "## Counts per tier",
        "",
        "| tier | total | parsed | parse-err | clean | w/findings | findings | per-parsed |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for tier in sorted(by_tier):
        b = by_tier[tier]
        per_parsed = b["findings"] / b["parsed"] if b["parsed"] else 0
        lines.append(
            f"| `{tier}` | {b['total']} | {b['parsed']} | {b['parse_errors']} | "
            f"{b['clean']} | {b['with_findings']} | {b['findings']} | {per_parsed:.2f} |"
        )

    lines += ["", "## Severity distribution per tier", "",
              "| tier | critical | high | medium | low |",
              "| --- | ---: | ---: | ---: | ---: |"]
    for tier in sorted(by_tier):
        s = by_tier[tier]["severity"]
        lines.append(f"| `{tier}` | {s.get('critical',0)} | {s.get('high',0)} | "
                     f"{s.get('medium',0)} | {s.get('low',0)} |")

    if any(by_tier[t]["parse_errors"] for t in by_tier):
        present_classes = [
            cls for cls in _PARSE_CLASS_ORDER
            if any(by_tier[t]["parse_classes"].get(cls, 0) for t in by_tier)
        ]
        lines += [
            "",
            "## Parse-error classes per tier",
            "",
            (
                "Each row is one tier; columns are parse-error classes plus the"
                + " tier's parse-error rate (parse-errors / total). The report"
                + " cites these as a finding — see `docs/state-of-compose.md`"
                + " methodology."
            ),
            "",
            "| tier | " + " | ".join(present_classes) + " | rate |",
            "| --- | " + " | ".join(["---:"] * len(present_classes)) + " | ---: |",
        ]
        for tier in sorted(by_tier):
            b = by_tier[tier]
            cells = [str(b["parse_classes"].get(cls, 0)) for cls in present_classes]
            rate = b["parse_errors"] / b["total"] if b["total"] else 0
            lines.append(f"| `{tier}` | " + " | ".join(cells) + f" | {rate:.1%} |")

    lines += [
        "",
        "## Top 10 rules per tier",
        "",
        f"`Impact` = severity weight × files-affected (within this tier). Weights: {_fmt_weights()}.",
        "",
    ]
    for tier in sorted(by_tier):
        rules = by_tier[tier]["rules"]
        if not rules:
            continue
        files_per_rule = by_tier[tier]["files_per_rule"]
        lines += [f"### `{tier}`", "",
                  "| Rule | Severity | Hits | Files | Impact |",
                  "| --- | --- | ---: | ---: | ---: |"]
        for rid, n in rules.most_common(10):
            sev = rule_severity.get(rid, "?")
            impact = SEVERITY_WEIGHT.get(sev, 0) * files_per_rule[rid]
            lines.append(f"| `{rid}` | {sev} | {n} | {files_per_rule[rid]} | {impact} |")
        lines.append("")

    (run_dir / "tier_summary.md").write_text("\n".join(lines))


def get_cl_version() -> str:
    try:
        out = subprocess.run([COMPOSE_LINT, "--version"], capture_output=True, text=True, timeout=5).stdout.strip()
        # `compose-lint --version` prints "compose-lint X.Y.Z"; strip the prefix
        return out.removeprefix("compose-lint ").strip() or out
    except Exception:
        return "unknown"


def main() -> int:
    if not FILES.exists() or not any(FILES.iterdir()):
        print(f"no files in {FILES} — run fetch.py first", file=sys.stderr)
        return 1

    paths = sorted(FILES.glob("*.yml"))
    print(f"linting {len(paths)} files with {WORKERS} workers", file=sys.stderr)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = RUNS / ts
    run_dir.mkdir(parents=True, exist_ok=True)
    results_path = run_dir / "results.jsonl"

    start = time.monotonic()
    results: list[dict] = []
    with results_path.open("w") as out, ProcessPoolExecutor(max_workers=WORKERS) as pool:
        futures = {pool.submit(lint_one, str(p)): p for p in paths}
        done = 0
        for fut in as_completed(futures):
            if time.monotonic() - start > GLOBAL_TIMEOUT_SECS:
                print("global lint timeout reached", file=sys.stderr)
                for f in futures:
                    f.cancel()
                break
            r = fut.result()
            results.append(r)
            out.write(json.dumps(r) + "\n")
            done += 1
            if done % 200 == 0:
                print(f"  linted {done}/{len(paths)}", file=sys.stderr)

    elapsed = time.monotonic() - start
    print(f"linted {len(results)} files in {elapsed:.1f}s", file=sys.stderr)

    index = load_index()
    summarize(run_dir, results, index, ts, elapsed)
    summarize_tiers(run_dir, results, index)

    (run_dir / "meta.json").write_text(json.dumps({
        "started_at": ts,
        "elapsed_seconds": elapsed,
        "compose_lint_version": get_cl_version(),
        "compose_lint_path": COMPOSE_LINT,
        "files_total": len(paths),
        "files_processed": len(results),
        "workers": WORKERS,
        "per_file_timeout": PER_FILE_TIMEOUT,
    }, indent=2))

    print(f"\nresults: {run_dir}", file=sys.stderr)
    print(f"  summary.md  ({(run_dir / 'summary.md').stat().st_size} bytes)", file=sys.stderr)
    print(f"  tier_summary.md  ({(run_dir / 'tier_summary.md').stat().st_size} bytes)", file=sys.stderr)
    print(f"  results.jsonl  ({results_path.stat().st_size} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
