#!/usr/bin/env python3
"""Render the State of Compose report charts as SVG into `docs/assets/`.

Reads a finished corpus run (the same `results.jsonl` + `index.jsonl` that
`make_tier_summary.py` consumes) and emits one SVG per figure embedded in
`docs/state-of-compose.md`. Aggregation is delegated to `run.aggregate_tiers`
so every chart and every table in the report share one source of truth — a
chart can never disagree with `tier_summary.md`.

Charts produced:
  findings-by-tier.svg      Share of files with >=1 finding, per tier.
  top-findings.svg          Top 10 rules by share of parsed files affected.
  severity-distribution.svg Findings by severity (share of all findings).
  parse-error-rate.svg      Parse-error rate, per tier.

matplotlib is an optional dependency: `pip install -e '.[corpus]'`. It never
enters the runtime wheel (PyYAML-only per CLAUDE.md).

Usage:
  python3 scripts/corpus/charts.py latest        # most recent run
  python3 scripts/corpus/charts.py 20260503T034026Z
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent))
from make_tier_summary import resolve_run  # noqa: E402
from run import aggregate_tiers, get_cl_version, load_index  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "docs" / "rules"
ASSETS = REPO_ROOT / "docs" / "assets"

# Tier order is the report's order (cleanest -> noisiest framing), not
# alphabetical, so charts read the same way the prose does.
TIER_ORDER = ("canonical", "popular", "selfhosted", "longtail")
SEVERITY_ORDER = ("critical", "high", "medium", "low")

# Severity palette: a warm red->amber ramp plus neutral grey for LOW. Chosen
# for contrast on white (GitHub / dev.to) and to keep CRITICAL visually loud.
SEVERITY_COLORS = {
    "critical": "#b1281f",
    "high": "#e06c00",
    "medium": "#e0a800",
    "low": "#8a8a8a",
}
PRIMARY = "#2563eb"   # default bar colour
ACCENT = "#b1281f"    # highlight (the bar that carries the headline)
GRID = "#e6e6e6"

_TITLE_RE = re.compile(r"^#\s*(CL-\d+):\s*(.+?)\s*$")


def rule_title(rule_id: str) -> str:
    """Human-readable rule name from the H1 of `docs/rules/<id>.md`.

    The rule doc is the single source of truth for titles; falls back to the
    bare id if the doc is missing or has no recognisable H1.
    """
    path = RULES_DIR / f"{rule_id}.md"
    if path.exists():
        for line in path.read_text().splitlines():
            m = _TITLE_RE.match(line)
            if m and m.group(1) == rule_id:
                return m.group(2)
    return rule_id


def _style() -> None:
    plt.rcParams.update({
        "svg.fonttype": "none",  # keep labels as selectable, crisp text
        "font.size": 11,
        "font.family": "sans-serif",
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.titlesize": 13,
        "axes.titleweight": "bold",
        "axes.titlepad": 12,
        "figure.dpi": 100,
    })


def _provenance(by_tier: dict[str, dict], run_dir: Path) -> str:
    parsed = sum(b["parsed"] for b in by_tier.values())
    return f"compose-lint {get_cl_version()}  ·  corpus {run_dir.name}  ·  n={parsed:,} parsed"


def _caption(fig: plt.Figure, text: str) -> None:
    """Stamp run provenance along the top edge.

    Top placement (not a footer) keeps it clear of x-axis tick labels and
    any below-axes legend, so it survives charts shared standalone on
    dev.to / social where the surrounding doc context is gone.
    """
    engine = fig.get_layout_engine()
    if engine is not None:
        engine.set(rect=(0, 0, 1, 0.93))  # reserve the top 7% for the caption
    fig.text(0.012, 0.985, text, fontsize=8, color="#999", ha="left", va="top")


def chart_findings_by_tier(by_tier: dict[str, dict], run_dir: Path) -> Path:
    tiers = [t for t in TIER_ORDER if t in by_tier]
    pct = [100 * by_tier[t]["with_findings"] / by_tier[t]["parsed"] for t in tiers]

    fig, ax = plt.subplots(figsize=(7.5, 4.4), layout="constrained")
    bars = ax.bar(tiers, pct, width=0.62, color=PRIMARY)
    for bar, p in zip(bars, pct):
        if p >= 99.95:  # 100% tier carries the headline; make it loud
            bar.set_color(ACCENT)
        ax.text(bar.get_x() + bar.get_width() / 2, p + 1.2, f"{p:.1f}%",
                ha="center", va="bottom", fontweight="bold", fontsize=11)

    ax.set_ylim(0, 108)
    ax.set_ylabel("Files with ≥1 finding (% of parsed)")
    ax.set_title("Every tier ships findings — even the cleanest is 83%")
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, color=GRID)
    ax.tick_params(length=0)
    _caption(fig, _provenance(by_tier, run_dir))
    return _save(fig, "findings-by-tier.svg")


def chart_top_findings(by_tier: dict[str, dict], rule_severity: dict[str, str],
                       run_dir: Path) -> Path:
    parsed = sum(b["parsed"] for b in by_tier.values())
    files_per_rule: Counter[str] = Counter()
    for b in by_tier.values():
        files_per_rule.update(b["files_per_rule"])

    top = files_per_rule.most_common(10)[::-1]  # reversed: largest at top in barh
    labels = [f"{rid}  ·  {rule_title(rid)}" for rid, _ in top]
    pct = [100 * n / parsed for _, n in top]
    colors = [SEVERITY_COLORS.get(rule_severity.get(rid, ""), "#8a8a8a")
              for rid, _ in top]

    fig, ax = plt.subplots(figsize=(8.8, 5.4), layout="constrained")
    ax.barh(range(len(top)), pct, color=colors)
    ax.set_yticks(range(len(top)), labels)
    for i, p in enumerate(pct):
        ax.text(p + 0.8, i, f"{p:.0f}%", va="center", fontsize=10)

    ax.set_xlim(0, 100)
    ax.set_xlabel("Files affected (% of parsed)")
    ax.set_title("Most common findings across the corpus")
    ax.set_axisbelow(True)
    ax.xaxis.grid(True, color=GRID)
    ax.tick_params(length=0)

    present = [s for s in SEVERITY_ORDER
               if any(rule_severity.get(rid) == s for rid, _ in top)]
    ax.legend(handles=[Patch(color=SEVERITY_COLORS[s], label=s.upper()) for s in present],
              loc="lower right", frameon=False, title="Severity")
    _caption(fig, _provenance(by_tier, run_dir))
    return _save(fig, "top-findings.svg")


def chart_severity_distribution(by_tier: dict[str, dict], run_dir: Path) -> Path:
    sev: Counter[str] = Counter()
    for b in by_tier.values():
        sev.update(b["severity"])
    total = sum(sev.get(s, 0) for s in SEVERITY_ORDER)

    fig, ax = plt.subplots(figsize=(8.8, 2.8), layout="constrained")
    left = 0.0
    for s in SEVERITY_ORDER:
        n = sev.get(s, 0)
        share = 100 * n / total if total else 0
        ax.barh(0, share, left=left, color=SEVERITY_COLORS[s], height=0.6)
        if share >= 4:  # only wide segments get an in-bar label
            ax.text(left + share / 2, 0, f"{s.upper()}\n{share:.1f}%",
                    ha="center", va="center", color="white",
                    fontweight="bold", fontsize=10)
        left += share

    ax.set_xlim(0, 100)
    ax.set_ylim(-0.5, 0.5)
    ax.set_yticks([])
    ax.set_xlabel("Share of all findings (%)")
    ax.set_title("Findings by severity — MEDIUM hardening misses dominate")
    ax.tick_params(length=0)

    # Legend carries exact counts so the slivers (CRITICAL, LOW) are still
    # readable even though they're too thin to label in-bar.
    handles = [Patch(color=SEVERITY_COLORS[s],
                     label=f"{s.upper()} — {sev.get(s, 0):,} ({100 * sev.get(s, 0) / total:.1f}%)")
               for s in SEVERITY_ORDER]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.35),
              ncol=4, frameon=False, fontsize=9)
    _caption(fig, _provenance(by_tier, run_dir))
    return _save(fig, "severity-distribution.svg")


def chart_parse_error_rate(by_tier: dict[str, dict], run_dir: Path) -> Path:
    tiers = [t for t in TIER_ORDER if t in by_tier]
    rate = [100 * by_tier[t]["parse_errors"] / by_tier[t]["total"]
            if by_tier[t]["total"] else 0 for t in tiers]
    top = max(rate) if rate else 0

    fig, ax = plt.subplots(figsize=(7.5, 4.4), layout="constrained")
    bars = ax.bar(tiers, rate, width=0.62, color=PRIMARY)
    for bar, r in zip(bars, rate):
        if r == top and top > 0:  # the longtail spike is the point
            bar.set_color(ACCENT)
        ax.text(bar.get_x() + bar.get_width() / 2, r + 0.15, f"{r:.1f}%",
                ha="center", va="bottom", fontweight="bold", fontsize=11)

    ax.set_ylim(0, top * 1.25 if top else 1)
    ax.set_ylabel("Files failing to parse as Compose (% of tier)")
    ax.set_title("Parse failures are a longtail phenomenon")
    ax.set_axisbelow(True)
    ax.yaxis.grid(True, color=GRID)
    ax.tick_params(length=0)
    _caption(fig, _provenance(by_tier, run_dir))
    return _save(fig, "parse-error-rate.svg")


def _save(fig: plt.Figure, name: str) -> Path:
    ASSETS.mkdir(parents=True, exist_ok=True)
    out = ASSETS / name
    fig.savefig(out, format="svg")
    plt.close(fig)
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.exit(__doc__)
    run_dir = resolve_run(argv[1])
    results_path = run_dir / "results.jsonl"
    if not results_path.exists():
        sys.exit(f"no results.jsonl in {run_dir}")

    _style()
    results = [json.loads(line) for line in results_path.open()]
    by_tier, rule_severity = aggregate_tiers(results, load_index())

    outs = [
        chart_findings_by_tier(by_tier, run_dir),
        chart_top_findings(by_tier, rule_severity, run_dir),
        chart_severity_distribution(by_tier, run_dir),
        chart_parse_error_rate(by_tier, run_dir),
    ]
    for out in outs:
        print(f"wrote {out.relative_to(REPO_ROOT)} ({out.stat().st_size} bytes)",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
