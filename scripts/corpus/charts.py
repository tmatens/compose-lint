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

With `--cover`, instead emits a blog cover banner (`cover.png`) into
`docs/publishing/assets/`.

matplotlib is an optional dependency: `pip install -e '.[corpus]'`. It never
enters the runtime wheel (PyYAML-only per CLAUDE.md).

Usage:
  python3 scripts/corpus/charts.py latest          # SVGs -> docs/assets/
  python3 scripts/corpus/charts.py 20260503T034026Z
  python3 scripts/corpus/charts.py 20260503T034026Z --png    # PNGs -> docs/publishing/assets/
  python3 scripts/corpus/charts.py 20260503T034026Z --cover  # cover.png -> docs/publishing/assets/

SVG is the default (vector, embedded in the report). `--png` emits raster
copies for blog uploads, since dev.to / Hashnode don't reliably render
raw-GitHub SVGs. Both formats stamp the compose-lint version from the run's
meta.json, so a chart shared standalone still names the rule set behind it.
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
ASSETS = REPO_ROOT / "docs" / "assets"            # SVGs embedded in the report
PNG_ASSETS = REPO_ROOT / "docs" / "publishing" / "assets"  # PNGs for blog upload

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


def _run_version(run_dir: Path) -> str:
    """compose-lint version that produced this run, from its meta.json.

    The provenance caption must reflect the version that *generated* the
    run (the report is pinned to it), not whatever happens to be installed
    now — otherwise re-rendering after a release would mis-stamp the pinned
    figures. Falls back to the live binary if meta.json is missing.
    """
    meta = run_dir / "meta.json"
    if meta.exists():
        try:
            return json.loads(meta.read_text()).get("compose_lint_version") or get_cl_version()
        except (OSError, ValueError):
            pass
    return get_cl_version()


def _provenance(by_tier: dict[str, dict], run_dir: Path) -> str:
    parsed = sum(b["parsed"] for b in by_tier.values())
    return f"compose-lint {_run_version(run_dir)}  ·  corpus {run_dir.name}  ·  n={parsed:,} parsed"


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


def chart_findings_by_tier(by_tier: dict[str, dict], run_dir: Path) -> tuple[plt.Figure, str]:
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
    return fig, "findings-by-tier"


def chart_top_findings(by_tier: dict[str, dict], rule_severity: dict[str, str],
                       run_dir: Path) -> tuple[plt.Figure, str]:
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
    return fig, "top-findings"


def chart_severity_distribution(by_tier: dict[str, dict], run_dir: Path) -> tuple[plt.Figure, str]:
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
    return fig, "severity-distribution"


def chart_parse_error_rate(by_tier: dict[str, dict], run_dir: Path) -> tuple[plt.Figure, str]:
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
    return fig, "parse-error-rate"


def chart_cover(by_tier: dict[str, dict], run_dir: Path) -> tuple[plt.Figure, str]:
    """Blog cover banner (~1000x420). Dark theme, data-driven from the run.

    Shows the "hardening triple" — the three ~90% controls the report leads
    with — so the cover reinforces the headline. Plain-language labels so it
    reads with no methodology, and it refreshes with the numbers.
    """
    bg, fg, mute, blue = "#0f172a", "#e2e8f0", "#94a3b8", "#3b82f6"
    triple = [
        ("CL-0007", "read-only filesystem"),
        ("CL-0006", "drop capabilities"),
        ("CL-0003", "no-new-privileges"),
    ]
    parsed = sum(b["parsed"] for b in by_tier.values())
    total = sum(b["total"] for b in by_tier.values())
    files_per_rule: Counter[str] = Counter()
    for b in by_tier.values():
        files_per_rule.update(b["files_per_rule"])

    fig = plt.figure(figsize=(10, 4.2))
    fig.patch.set_facecolor(bg)
    fig.text(0.055, 0.88, "State of Docker\nCompose Security", fontsize=26,
             fontweight="bold", color=fg, va="top", linespacing=1.12)
    fig.text(0.055, 0.50, f"An empirical scan of {total:,} public Compose files",
             fontsize=13.5, color=mute, va="top")
    fig.text(0.055, 0.36, "9 in 10 files skip all three of the\nbasic hardening flags.",
             fontsize=14, color=fg, va="top", linespacing=1.4)
    fig.text(0.055, 0.085, "compose-lint   ·   OWASP / CIS-grounded   ·   MIT",
             fontsize=10.5, color=mute, va="bottom")

    # One labelled bar per flag. Label sits above its bar so the full name fits.
    ax = fig.add_axes((0.56, 0.13, 0.40, 0.66))
    ax.set_facecolor(bg)
    n = len(triple)
    for i, (rid, label) in enumerate(triple):
        p = 100 * files_per_rule.get(rid, 0) / parsed if parsed else 0
        y = n - 1 - i
        ax.barh(y, p, height=0.34, color=blue)
        ax.text(0, y + 0.30, label, ha="left", va="bottom", color=fg, fontsize=11)
        ax.text(p + 2, y, f"{p:.0f}%", ha="left", va="center", color=fg,
                fontsize=11, fontweight="bold")
    ax.set_xlim(0, 116)
    ax.set_ylim(-0.5, n + 0.35)
    ax.axis("off")
    ax.text(0, n - 0.05, "missing, % of files", color=mute, fontsize=9.5,
            va="bottom", ha="left")
    return fig, "cover"


def _save(fig: plt.Figure, name: str, fmt: str, out_dir: Path, dpi: int) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{name}.{fmt}"
    # facecolor=fig's own so the dark cover keeps its background, not white.
    fig.savefig(out, format=fmt, dpi=dpi, facecolor=fig.get_facecolor())
    plt.close(fig)
    return out


def main(argv: list[str]) -> int:
    png = "--png" in argv[1:]
    cover = "--cover" in argv[1:]
    positional = [a for a in argv[1:] if not a.startswith("-")]
    if len(positional) != 1:
        sys.exit(__doc__)
    run_dir = resolve_run(positional[0])
    results_path = run_dir / "results.jsonl"
    if not results_path.exists():
        sys.exit(f"no results.jsonl in {run_dir}")

    _style()
    results = [json.loads(line) for line in results_path.open()]
    by_tier, rule_severity = aggregate_tiers(results, load_index())

    if cover:
        # Blog cover banner only -> PNG in docs/publishing/assets/.
        fig, name = chart_cover(by_tier, run_dir)
        out = _save(fig, name, "png", PNG_ASSETS, 200)
        print(f"wrote {out.relative_to(REPO_ROOT)} ({out.stat().st_size} bytes)",
              file=sys.stderr)
        return 0

    # SVG (vector) for the report; PNG (raster, 2x dpi) for blog uploads —
    # dev.to / Hashnode don't reliably render raw-GitHub SVGs.
    fmt, out_dir, dpi = ("png", PNG_ASSETS, 192) if png else ("svg", ASSETS, 100)

    figures = [
        chart_findings_by_tier(by_tier, run_dir),
        chart_top_findings(by_tier, rule_severity, run_dir),
        chart_severity_distribution(by_tier, run_dir),
        chart_parse_error_rate(by_tier, run_dir),
    ]
    for fig, name in figures:
        out = _save(fig, name, fmt, out_dir, dpi)
        print(f"wrote {out.relative_to(REPO_ROOT)} ({out.stat().st_size} bytes)",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
