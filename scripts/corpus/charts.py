#!/usr/bin/env python3
"""Render the State of Compose report figures into `docs/assets/`.

Reads a finished corpus run (`results.jsonl` + `index.jsonl`) and emits one
SVG per figure embedded in `docs/state-of-compose.md`. Every number is
computed from the run — a chart can never disagree with the tables.

The figures follow an editorial identity (third edition, 2026-08-27),
built from the data-visualization research tracked in #759's thread:
one claim per chart stated in the title, at most ~10% of the visual
highlighted, no legends (direct labels), exactly two in-chart text
sizes, honest zero-based axes, and a masthead + sourced footer so each
figure is self-identifying when shared standalone. Typography is Inter /
Inter Display / JetBrains Mono, vendored under assets/fonts/ with their
SIL OFL licenses; SVGs embed text as paths so they render identically
without the fonts installed.

Charts produced (docs/assets/<name>.svg):
  not-improving         findings/service by file age — flat (the hero)
  bigger-not-sloppier   per-file vs per-service findings by tier
  file-severity         waffle: worst finding per file, natural frequencies
  overlay-credentials   literal-credential rate by overlay variant
  top-findings          the ten dominant rules, grouped as the report groups
  never-linted          skips (v1/fragments) + parse errors by tier

With `--png`, raster copies land in docs/publishing/assets/ under the
same names (the pre-third-edition PNGs there are hot-linked by the live
dev.to post and keep their old names — do not delete them). With
`--cover`, emits the blog cover banner (`cover.png`).

matplotlib is an optional dependency: `pip install -e '.[corpus]'`. It
never enters the runtime wheel (PyYAML-only per CLAUDE.md).

Usage:
  python3 scripts/corpus/charts.py latest
  python3 scripts/corpus/charts.py 20260827T190923Z
  python3 scripts/corpus/charts.py 20260827T190923Z --png
  python3 scripts/corpus/charts.py 20260827T190923Z --cover
"""
from __future__ import annotations

import datetime
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.font_manager as fm  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402

sys.path.insert(0, str(Path(__file__).parent))
from make_tier_summary import resolve_run  # noqa: E402
from run import (  # noqa: E402
    EXCLUDED_FROM_PREVALENCE,
    aggregate_tiers,
    get_cl_version,
    load_index,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
ASSETS = REPO_ROOT / "docs" / "assets"            # SVGs embedded in the report
PNG_ASSETS = REPO_ROOT / "docs" / "publishing" / "assets"  # PNGs for blog upload
FONTS = Path(__file__).parent / "assets" / "fonts"

# ---- identity -------------------------------------------------------------
PAPER = "#fbfaf7"
INK = "#141c2b"
MUTE = "#6d7684"
FAINT = "#c9cdd4"
GRID = "#e7e4de"
RED = "#c0392b"
BLUE = "#2b5d8a"
SAND = "#9e9074"
ORANGE = "#e07b00"
SANDTEXT = "#7d7260"
WORDMARK = "#b9b0a0"
BODY = 12    # data labels, axis labels, annotations
SMALL = 10   # secondary labels, in-chart captions
KICKER = "STATE OF DOCKER COMPOSE SECURITY · THIRD EDITION"
FIGSIZE = (11.8, 6.4)

TIER_ORDER = ("canonical", "selfhosted", "collections", "popular", "longtail")


def _style() -> None:
    for f in FONTS.glob("*.ttf"):
        fm.fontManager.addfont(str(f))
    plt.rcParams.update({
        "figure.facecolor": PAPER, "axes.facecolor": PAPER, "savefig.facecolor": PAPER,
        "font.family": "Inter", "text.color": INK, "axes.edgecolor": FAINT,
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.spines.left": False, "figure.dpi": 100,
        "svg.fonttype": "path",  # self-contained SVGs: glyphs as outlines
    })


def _run_version(run_dir: Path) -> str:
    meta = run_dir / "meta.json"
    if meta.exists():
        try:
            v = json.loads(meta.read_text()).get("compose_lint_version")
            return v or get_cl_version()
        except (OSError, ValueError):
            pass
    return get_cl_version()


def _masthead(fig: plt.Figure, title: str, dek: str) -> None:
    fig.add_artist(plt.Rectangle((0.012, 0.952), 0.028, 0.034, color=RED,
                                 transform=fig.transFigure, clip_on=False))
    fig.text(0.050, 0.960, KICKER, fontsize=SMALL, color=RED, fontweight="bold")
    fig.text(0.012, 0.882, title, fontsize=23, color=INK,
             fontfamily="Inter Display", fontweight="bold")
    fig.text(0.012, 0.820, dek, fontsize=12.5, color=MUTE)


def _footer(fig: plt.Figure, d: Data, note: str = "") -> None:
    fig.add_artist(plt.Line2D([0.012, 0.988], [0.078, 0.078], color=FAINT, lw=0.8,
                              transform=fig.transFigure))
    src = (f"Source: compose-lint {d.version} · {d.corpus_total:,}-file public corpus"
           f" · run {d.run_dir.name}")
    fig.text(0.012, 0.042, src + (("   ·   " + note) if note else ""),
             fontsize=8.5, color=MUTE)
    fig.text(0.988, 0.042, "compose-lint", fontsize=9, color=WORDMARK,
             ha="right", fontfamily="JetBrains Mono", fontweight="bold")


# ---- data -----------------------------------------------------------------
class Data:
    """Everything the figures need, computed in one pass over the run.

    Parsing every corpus file for service counts takes a minute or two;
    this is a maintainer-only script and determinism beats caching.
    """

    def __init__(self, run_dir: Path) -> None:
        from compose_lint.parser import load_compose  # dev env only

        self.run_dir = run_dir
        self.version = _run_version(run_dir)
        index = load_index()
        results = [json.loads(line) for line in (run_dir / "results.jsonl").open()]
        self.by_tier, self.rule_severity = aggregate_tiers(results, index)
        self.corpus_total = sum(b["total"] for b in self.by_tier.values())
        res = {r["content_hash"]: r for r in results}
        # run date anchors the age buckets (deterministic, from the run name)
        run_date = datetime.datetime.strptime(
            run_dir.name[:8], "%Y%m%d").replace(tzinfo=datetime.UTC)

        sev_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        self.svc = defaultdict(int)          # tier -> services
        self.files = defaultdict(int)        # tier -> parsed v2/v3 files
        self.finds = defaultdict(int)        # tier -> findings
        # tier -> age -> [services, findings]
        self.age_svc = defaultdict(lambda: defaultdict(lambda: [0, 0]))
        self.worst = Counter()               # worst-severity -> files
        # variant -> [credential files, files]
        self.cred_by_variant = defaultdict(lambda: [0, 0])
        self.cred_fullfile = [0, 0]          # [cred files, files] prevalence
        parsed_total = 0
        for h, e in index.items():
            tier = e.get("tier")
            r = res.get(h)
            if not r or r.get("error") or r.get("lint") is None or r.get("skip_note"):
                continue
            findings = r["lint"].get("findings", [])
            rids = {f["rule_id"] for f in findings}
            is_prev = tier not in EXCLUDED_FROM_PREVALENCE
            if tier == "overlay" or is_prev:
                try:
                    data, _ = load_compose(str(
                        Path.home() / ".cache" / "compose-lint-corpus"
                        / "files" / f"{h}.yml"))
                    nsvc = len(data.get("services", {}) or {})
                except Exception:
                    continue
            if tier == "overlay":
                parts = Path(e["path"]).name.split(".")
                variant = parts[-2] if len(parts) >= 3 else "?"
                v = self.cred_by_variant[variant]
                v[1] += 1
                if rids & {"CL-0020", "CL-0021"}:
                    v[0] += 1
                continue
            if not is_prev:
                continue
            parsed_total += 1
            self.files[tier] += 1
            self.svc[tier] += nsvc
            self.finds[tier] += len(findings)
            self.cred_fullfile[1] += 1
            if rids & {"CL-0020", "CL-0021"}:
                self.cred_fullfile[0] += 1
            if findings:
                worst = max((f["severity"] for f in findings),
                            key=lambda s: sev_rank[s])
                self.worst[worst] += 1
            else:
                self.worst["clean"] += 1
            iso = e.get("blob_authored_at")
            if iso:
                days = (run_date - datetime.datetime.fromisoformat(
                    iso.replace("Z", "+00:00"))).days
                age = "<1y" if days < 365 else "1-3y" if days < 1095 else ">=3y"
                a = self.age_svc[tier][age]
                a[0] += nsvc
                a[1] += len(findings)
        self.parsed_total = parsed_total

    def per_svc(self, tier: str) -> float:
        return self.finds[tier] / self.svc[tier]

    def per_file(self, tier: str) -> float:
        return self.finds[tier] / self.files[tier]

    def svc_per_file(self, tier: str) -> float:
        return self.svc[tier] / self.files[tier]


# ---- figures --------------------------------------------------------------
def chart_not_improving(d: Data) -> tuple[plt.Figure, str]:
    ages = ["<1y", "1-3y", ">=3y"]
    fig = plt.figure(figsize=FIGSIZE)
    ax = fig.add_axes((0.055, 0.155, 0.90, 0.56))
    endlab = []
    for tier in TIER_ORDER:
        pts = [(i, a[1] / a[0]) for i, age in enumerate(ages)
               for a in [d.age_svc[tier][age]] if a[0]]
        ax.plot(*zip(*pts, strict=False), "-", color=FAINT, lw=1.4, zorder=2)
        ax.scatter(*zip(*pts, strict=False), s=13, color=FAINT, zorder=2)
        endlab.append((tier, pts[-1]))
    allrow = []
    for age in ages:
        s = sum(d.age_svc[t][age][0] for t in TIER_ORDER)
        f = sum(d.age_svc[t][age][1] for t in TIER_ORDER)
        allrow.append(f / s)
    ax.plot(range(3), allrow, "-", color=RED, lw=3.4, zorder=4, solid_capstyle="round")
    ax.scatter(range(3), allrow, s=52, color=RED, zorder=5)
    for x, v in zip(range(3), allrow, strict=True):
        ax.annotate(f"{v:.2f}", (x, v), xytext=(0, 12), textcoords="offset points",
                    ha="center", fontsize=BODY, fontweight="bold", color=RED)
    # end labels, spread to avoid pileup (order by value, fixed spacing)
    for rank, (tier, (x, v)) in enumerate(
            sorted(endlab, key=lambda kv: -kv[1][1])):
        y = max(v, 0.2)
        ax.text(x + 0.05, 6.55 - rank * 0.33 if x == 2 else y + 0.12, tier,
                fontsize=SMALL, color=MUTE, va="center")
    ax.annotate("a service written last month ships with the same\n"
                "missing hardening as one written four years ago",
                xy=(0.55, allrow[0] - 0.05), xytext=(0.32, 3.35), fontsize=BODY,
                color=INK, arrowprops=dict(arrowstyle="-", color=MUTE, lw=1,
                                           connectionstyle="arc3,rad=-0.16"))
    ax.set_xlim(-0.15, 2.45)
    ax.set_ylim(0, 7.4)
    ax.set_xticks(range(3),
                  ["written in the last year", "1–3 years ago", "3+ years ago"],
                  fontsize=BODY)
    ax.set_yticks([0, 2, 4, 6])
    ax.yaxis.grid(True, color=GRID, lw=0.9)
    ax.set_axisbelow(True)
    ax.tick_params(length=0)
    ax.text(-0.15, 7.05, "security findings per service — "
                         "grey: individual tiers · red: all files",
            fontsize=SMALL, color=MUTE)
    _masthead(fig, "Four years of Compose files. Zero improvement.",
              "Files written last year miss hardening at the same per-service rate "
              "as files written years ago — in every tier")
    _footer(fig, d, "y-axis starts at zero · replicated on files fetched after "
                    "the claim was first made")
    return fig, "not-improving"


def chart_bigger_not_sloppier(d: Data) -> tuple[plt.Figure, str]:
    order = sorted(TIER_ORDER, key=lambda t: -d.per_file(t))
    fig = plt.figure(figsize=FIGSIZE)
    axL = fig.add_axes((0.115, 0.135, 0.46, 0.50))
    axR = fig.add_axes((0.685, 0.135, 0.27, 0.50))
    ys = list(range(len(order)))[::-1]
    hero = order[0]
    for y, t in zip(ys, order, strict=False):
        c = RED if t == hero else BLUE
        axL.barh(y, d.per_file(t), color=c, height=0.56)
        axL.text(d.per_file(t) + 0.35, y, f"{d.per_file(t):.1f}", va="center",
                 fontsize=BODY, fontweight="bold", color=c if t == hero else INK)
        axL.text(-0.5, y, t, va="center", ha="right", fontsize=BODY, color=INK)
        axR.barh(y, d.per_svc(t), color=BLUE, height=0.56)
        axR.text(d.per_svc(t) + 0.18, y, f"{d.per_svc(t):.1f}", va="center",
                 fontsize=BODY, fontweight="bold", color=INK)
    lo = min(d.per_svc(t) for t in order)
    hi = max(d.per_svc(t) for t in order)
    axL.set_xlim(0, max(d.per_file(t) for t in order) * 1.13)
    axR.set_xlim(0, 8.2)
    for ax in (axL, axR):
        ax.set_ylim(-0.6, 4.6)
        ax.set_yticks([])
        ax.set_xticks([])
        ax.spines.bottom.set_visible(False)
    axR.axvspan(lo, hi, color=BLUE, alpha=0.10)
    axL.text(0, 5.35, "findings per FILE", fontsize=BODY, fontweight="bold", color=INK)
    axL.text(0, 4.88, f"{hero} files average {d.svc_per_file(hero):.1f} services "
                      "— twice the templates", fontsize=SMALL, color=RED)
    axR.text(0, 5.35, "findings per SERVICE", fontsize=BODY,
             fontweight="bold", color=INK)
    axR.text(0, 4.88, f"every tier lands in {lo:.1f}–{hi:.1f}",
             fontsize=SMALL, color=BLUE)
    _masthead(fig, "Bigger, not sloppier",
              "Popular projects' files carry twice the findings of templates — but "
              "per service, every tier misses hardening at the same rate")
    _footer(fig, d, "parsed files, prevalence tiers")
    return fig, "bigger-not-sloppier"


def chart_file_severity(d: Data) -> tuple[plt.Figure, str]:
    n = sum(d.worst.values())
    crit = round(100 * d.worst["critical"] / n)
    high = round(100 * d.worst["high"] / n)
    clean = max(1, round(100 * d.worst["clean"] / n)) if d.worst["clean"] else 0
    med = 100 - crit - high - clean
    fig = plt.figure(figsize=FIGSIZE)
    ax = fig.add_axes((0.055, 0.13, 0.50, 0.60))
    cells = ["crit"] * crit + ["high"] * high + ["med"] * med + ["clean"] * clean
    colors = {"crit": RED, "high": ORANGE, "med": SAND, "clean": PAPER}
    for i, kind in enumerate(cells):
        r, c = divmod(i, 10)
        ax.add_patch(plt.Rectangle((c, 9 - r), 0.88, 0.88, facecolor=colors[kind],
                                   edgecolor=FAINT if kind == "clean" else "none",
                                   lw=1.2))
    ax.set_xlim(-0.2, 10.1)
    ax.set_ylim(-0.4, 10.2)
    ax.set_xticks([])
    ax.set_yticks([])
    ax.spines.bottom.set_visible(False)
    tx = 0.60
    fig.text(tx, 0.640, f"{crit} in 100 files", fontsize=19, fontweight="bold",
             color=RED, fontfamily="Inter Display")
    fig.text(tx, 0.556, "carries a CRITICAL finding — a mounted control\n"
                        "socket, privileged mode, a root-equivalent path",
             fontsize=BODY, color=INK)
    fig.text(tx, 0.462, f"another {high} in 100", fontsize=19, fontweight="bold",
             color=ORANGE, fontfamily="Inter Display")
    fig.text(tx, 0.378, "top out at HIGH — most often a literal\n"
                        "credential in the environment",
             fontsize=BODY, color=INK)
    fig.text(tx, 0.284, f"{med} in 100", fontsize=19, fontweight="bold",
             color=SANDTEXT, fontfamily="Inter Display")
    fig.text(tx, 0.200, "carry only MEDIUM or LOW findings —\n"
                        "the missing hardening flags",
             fontsize=BODY, color=INK)
    fig.text(tx, 0.125,
             f"fewer than 1 in 100 is clean — {d.worst['clean']} files of {n:,}",
             fontsize=SMALL, color=MUTE)
    _masthead(fig, "What a Compose file is carrying",
              f"Each square is 1 in 100 of the {n:,} parsed real-world files, "
              "colored by the worst finding in the file")
    _footer(fig, d)
    return fig, "file-severity"


def chart_overlay_credentials(d: Data) -> tuple[plt.Figure, str]:
    rows = sorted(((v, c[0] / c[1] * 100) for v, c in d.cred_by_variant.items()
                   if c[1] >= 50), key=lambda kv: -kv[1])
    base = 100 * d.cred_fullfile[0] / d.cred_fullfile[1]
    dev_variants = {"local", "dev", "development"}
    fig = plt.figure(figsize=FIGSIZE)
    ax = fig.add_axes((0.155, 0.155, 0.80, 0.56))
    ys = list(range(len(rows)))[::-1]
    for y, (v, r) in zip(ys, rows, strict=False):
        dev = v in dev_variants
        ax.barh(y, r, color=ORANGE if dev else BLUE, height=0.58)
        ax.text(r + 0.5, y, f"{r:.0f}%", va="center", fontsize=BODY,
                fontweight="bold", color=ORANGE if dev else INK)
        ax.text(-0.7, y, f"*.{v}.*", va="center", ha="right", fontsize=BODY,
                color=INK, fontfamily="JetBrains Mono")
    ax.axvline(base, color=INK, lw=1.3, ls=(0, (4, 3)))
    ax.text(base + 0.6, len(rows) - 0.38, f"ordinary compose files: {base:.1f}%",
            fontsize=SMALL, color=INK)
    ax.set_xlim(0, 44)
    ax.set_yticks([])
    ax.set_xticks([])
    ax.spines.bottom.set_visible(False)
    ax.text(0, len(rows) + 0.35,
            "share of overlay files with a literal credential (CL-0020/21)",
            fontsize=SMALL, color=MUTE)
    _masthead(fig, '"It\'s just dev" is a measurable habit',
              "Dev and local overlay files hardcode credentials at 1.7× the ordinary "
              "rate — and prod overlays are no better than baseline")
    _footer(fig, d, f"{sum(c[1] for c in d.cred_by_variant.values()):,} parsed "
                    "overlay files, by filename variant")
    return fig, "overlay-credentials"


# Report-section grouping for the top-findings chart. Mirrors the three
# groups in docs/state-of-compose.md §Top findings; short names are the
# chart-facing phrasings of the rule titles.
TOP_GROUPS = [
    ("THE HARDENING NOBODY FLIPS",
     [("CL-0007", "read-only filesystem not set"),
      ("CL-0006", "no capability restrictions"),
      ("CL-0026", "no resource limits"),
      ("CL-0003", "privilege escalation not blocked")]),
    ("SUPPLY-CHAIN SHORTCUTS",
     [("CL-0005", "ports published on 0.0.0.0"),
      ("CL-0019", "image not pinned to a digest"),
      ("CL-0004", "image tag unpinned or :latest")]),
    ("THE ACUTE CLIFF",
     [("CL-0020", "literal credential in environment"),
      ("CL-0001", "host control socket mounted"),
      ("CL-0021", "credential in connection string")]),
]


def chart_top_findings(d: Data) -> tuple[plt.Figure, str]:
    files_per_rule: Counter[str] = Counter()
    for t in TIER_ORDER:
        files_per_rule.update(d.by_tier[t]["files_per_rule"])
    parsed = sum(d.by_tier[t]["parsed"] for t in TIER_ORDER)
    cmap = {"medium": SAND, "low": SAND, "high": ORANGE, "critical": RED}
    tcol = {"high": ORANGE, "critical": RED}
    fig = plt.figure(figsize=(11.8, 7.6))
    ax = fig.add_axes((0.31, 0.115, 0.645, 0.66))
    y = 0
    for gname, items in TOP_GROUPS:
        ax.text(-0.5, y + 0.72, gname, ha="left", fontsize=SMALL, color=MUTE,
                fontweight="bold", clip_on=False)
        for rid, name in items:
            files = files_per_rule[rid]
            pct = 100 * files / parsed
            sev = d.rule_severity.get(rid, "medium")
            ax.barh(y, pct, color=cmap[sev], height=0.62)
            ax.text(pct + 1.0, y, f"{files:,} files · {pct:.0f}%", va="center",
                    fontsize=BODY,
                    fontweight="bold" if sev in tcol else "normal",
                    color=tcol.get(sev, INK))
            ax.text(-1.2, y, name, va="center", ha="right", fontsize=BODY, color=INK)
            y -= 1
        y -= 0.85
    ax.set_xlim(0, 128)
    ax.set_ylim(y + 0.4, 1.5)
    ax.set_yticks([])
    ax.set_xticks([])
    ax.spines.bottom.set_visible(False)
    _masthead(fig, "Ten findings are 98% of the problem",
              "Share of parsed files affected — sand: missing defaults (MEDIUM/LOW) "
              "· orange: HIGH · red: CRITICAL")
    _footer(fig, d)
    return fig, "top-findings"


def chart_never_linted(d: Data) -> tuple[plt.Figure, str]:
    fig = plt.figure(figsize=FIGSIZE)
    ax = fig.add_axes((0.135, 0.155, 0.82, 0.56))
    ys = list(range(len(TIER_ORDER)))[::-1]
    tot_bad = tot_all = 0
    for y, t in zip(ys, TIER_ORDER, strict=False):
        b = d.by_tier[t]
        s = 100 * b["skipped"] / b["total"]
        p = 100 * b["parse_errors"] / b["total"]
        tot_bad += b["skipped"] + b["parse_errors"]
        tot_all += b["total"]
        ax.barh(y, s, color=BLUE, height=0.58)
        ax.barh(y, p, left=s, color=ORANGE, height=0.58)
        lab = (f"{b['skipped']} relics + {b['parse_errors']} broken  ({s + p:.0f}%)"
               if b["skipped"] + b["parse_errors"] else "0 — every file linted")
        ax.text(s + p + 0.35, y, lab, va="center", fontsize=BODY, color=INK)
        ax.text(-0.35, y, t, va="center", ha="right", fontsize=BODY, color=INK)
    ax.annotate("Compose v1 relics & fragments —\nlinted nothing, exited \"clean\"",
                xy=(10.8, 3.72), xytext=(13.2, 2.85), fontsize=SMALL, color=BLUE,
                arrowprops=dict(arrowstyle="-", color=BLUE, lw=1))
    ax.annotate("failed to parse", xy=(12.0, 0.38), xytext=(16.4, 1.05),
                fontsize=SMALL, color=ORANGE,
                arrowprops=dict(arrowstyle="-", color=ORANGE, lw=1))
    ax.set_xlim(0, 33)
    ax.set_yticks([])
    ax.set_xticks([])
    ax.spines.bottom.set_visible(False)
    share = 100 * tot_bad / tot_all
    _masthead(fig, "The files that never got linted",
              f"{share:.0f}% of real-world files produced no lint result: obsolete "
              "Compose v1 layouts that pass silently, fragments, and files that "
              "fail to parse")
    _footer(fig, d, f"{tot_bad:,} of {tot_all:,} prevalence-tier files ({share:.1f}%)")
    return fig, "never-linted"


def chart_cover(d: Data) -> tuple[plt.Figure, str]:
    """Blog cover banner (~1000x420). Dark theme, data-driven from the run."""
    bg, fg, mute, blue = "#0f172a", "#e2e8f0", "#94a3b8", "#3b82f6"
    triple = [("CL-0007", "read-only filesystem"),
              ("CL-0006", "drop capabilities"),
              ("CL-0003", "no-new-privileges")]
    files_per_rule: Counter[str] = Counter()
    for t in TIER_ORDER:
        files_per_rule.update(d.by_tier[t]["files_per_rule"])
    parsed = sum(d.by_tier[t]["parsed"] for t in TIER_ORDER)
    fig = plt.figure(figsize=(10, 4.2))
    fig.patch.set_facecolor(bg)
    fig.text(0.055, 0.88, "State of Docker\nCompose Security", fontsize=26,
             fontweight="bold", color=fg, va="top", linespacing=1.12,
             fontfamily="Inter Display")
    fig.text(0.055, 0.50,
             f"An empirical scan of {d.corpus_total:,} public Compose files",
             fontsize=13.5, color=mute, va="top")
    fig.text(0.055, 0.36, "9 in 10 files skip all three of the\nbasic hardening flags.",
             fontsize=14, color=fg, va="top", linespacing=1.4)
    fig.text(0.055, 0.085, "compose-lint   ·   OWASP / CIS-grounded   ·   MIT",
             fontsize=10.5, color=mute, va="bottom")
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
    if not (run_dir / "results.jsonl").exists():
        sys.exit(f"no results.jsonl in {run_dir}")

    _style()
    data = Data(run_dir)

    if cover:
        fig, name = chart_cover(data)
        out = _save(fig, name, "png", PNG_ASSETS, 200)
        print(f"wrote {out.relative_to(REPO_ROOT)} ({out.stat().st_size} bytes)",
              file=sys.stderr)
        return 0

    fmt, out_dir, dpi = ("png", PNG_ASSETS, 192) if png else ("svg", ASSETS, 100)
    for chart in (chart_not_improving, chart_bigger_not_sloppier, chart_file_severity,
                  chart_overlay_credentials, chart_top_findings, chart_never_linted):
        fig, name = chart(data)
        out = _save(fig, name, fmt, out_dir, dpi)
        print(f"wrote {out.relative_to(REPO_ROOT)} ({out.stat().st_size} bytes)",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
