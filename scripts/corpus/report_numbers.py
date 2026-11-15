#!/usr/bin/env python3
"""Compute the State of Compose report's numbers from a finished corpus run.

`run.py` writes `summary.md` and `tier_summary.md`. This script computes the
figures those two do not carry: per-service rates, file-age buckets, the
overlay lane, the replication lane, repo-resampling intervals and, with
`--base`, the same-files delta between two runs. Every table in
`docs/state-of-compose.md` comes from `run.py`'s summaries or from this
output, so a figure in the report can be traced to a run.

Prints JSON on stdout: counts, rates and rule ids only. No file content,
repo name or path from the corpus is printed.

Usage:
  python scripts/corpus/report_numbers.py latest
  python scripts/corpus/report_numbers.py 20261115T050406Z --base 20261115T050637Z

Run it with the Python that holds the compose-lint version that made the run,
so service counts come from the same parser. Requires the corpus cache.
"""
import datetime
import json
import random
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

from compose_lint.parser import load_compose

sys.path.insert(0, str(Path(__file__).parent))
from make_tier_summary import resolve_run  # noqa: E402
from run import EXCLUDED_FROM_PREVALENCE as EXCL  # noqa: E402
from run import SNAPSHOT_DATE as SNAPSHOT  # noqa: E402

CACHE = Path.home() / ".cache" / "compose-lint-corpus"
# index.jsonl is append-ordered by sweep. The first 5,417 entries are the
# second edition's corpus (the shallow, 200-hit longtail sweep). Entries from
# position 9,001 on were added by the deep sweep, after the tier-attribution
# rules were frozen: their longtail files are the replication lane.
SHALLOW_END = 5417
FRESH_START = 9001
TIERS = ("canonical", "selfhosted", "collections", "popular", "longtail")
RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

args = [a for a in sys.argv[1:] if not a.startswith("-")]
if len(args) not in (1, 2) or (len(args) == 2 and "--base" not in sys.argv):
    sys.exit(__doc__)
run_dir = resolve_run(args[0])
base_dir = resolve_run(args[1]) if len(args) == 2 else None
index_list = [json.loads(l) for l in (CACHE / "index.jsonl").open()]
index = {e["content_hash"]: e for e in index_list}
order = {e["content_hash"]: i for i, e in enumerate(index_list)}
res = {}
for l in (run_dir / "results.jsonl").open():
    r = json.loads(l)
    res[r["content_hash"]] = r


def status(r):
    if r.get("error") == "usage_or_parse":
        return "parse_error"
    if r.get("error"):
        return "crash:" + r["error"]
    if r.get("lint") is None:
        return "crash:nolint"
    if r.get("skip_note"):
        return "skipped"
    return "parsed"


def age_days(e):
    iso = e.get("blob_authored_at")
    if not iso:
        return None
    return (SNAPSHOT - datetime.datetime.fromisoformat(iso.replace("Z", "+00:00"))).days


def bucket3(d):
    return "<1y" if d < 365 else "1-3y" if d < 1095 else ">=3y"


def nsvc(h):
    try:
        data, _ = load_compose(str(CACHE / "files" / f"{h}.yml"))
        return len(data.get("services", {}) or {})
    except Exception:
        return None


def pct(a, b, nd=1):
    return round(100 * a / b, nd) if b else None


out = {}
meta = json.loads((run_dir / "meta.json").read_text())
out["meta"] = {k: meta[k] for k in ("started_at", "compose_lint_version", "files_total", "files_processed")}

# ---- per-file records -------------------------------------------------------
recs = {}
for h, e in index.items():
    r = res[h]
    st = status(r)
    f = r["lint"]["findings"] if st == "parsed" else []
    recs[h] = {
        "tier": e["tier"], "repo": e["repo"], "path": e["path"], "status": st,
        "findings": f, "rids": {x["rule_id"] for x in f},
        "age": age_days(e), "skip": r.get("skip_note", ""), "stderr": r.get("stderr", ""),
    }
out["status_all"] = Counter(v["status"] for v in recs.values())
out["tier_sizes"] = Counter(v["tier"] for v in recs.values())

prevl = {h: v for h, v in recs.items() if v["tier"] not in EXCL}
parsed = {h: v for h, v in prevl.items() if v["status"] == "parsed"}

# service counts (prevalence parsed + overlay parsed)
svc = {}
for h, v in recs.items():
    if v["status"] == "parsed" and (v["tier"] not in EXCL or v["tier"] == "overlay"):
        svc[h] = nsvc(h)
out["svc_parse_failures"] = sum(1 for x in svc.values() if x is None)

# ---- A. overview ------------------------------------------------------------
counts = [len(v["findings"]) for v in parsed.values()]
sev = Counter(x["severity"] for v in parsed.values() for x in v["findings"])
total = sum(counts)
A = {
    "prevalence_total": len(prevl),
    "parsed": len(parsed),
    "skipped": sum(1 for v in prevl.values() if v["status"] == "skipped"),
    "parse_errors": sum(1 for v in prevl.values() if v["status"] == "parse_error"),
    "other": sum(1 for v in prevl.values() if v["status"].startswith("crash")),
    "with_findings": sum(1 for c in counts if c),
    "clean": sum(1 for c in counts if not c),
    "total_findings": total,
    "mean": round(total / len(parsed), 2),
    "median": statistics.median(counts),
    "max": max(counts),
    "severity": dict(sev),
    "severity_share": {k: pct(n, total) for k, n in sev.items()},
}
A["with_findings_pct"] = pct(A["with_findings"], A["parsed"], 2)
worst = Counter()
for v in parsed.values():
    worst[max((x["severity"] for x in v["findings"]), key=RANK.get) if v["findings"] else "clean"] += 1
A["worst"] = dict(worst)
A["worst_pct"] = {k: pct(n, len(parsed), 2) for k, n in worst.items()}
A["files_with_critical_pct"] = pct(worst["critical"], len(parsed), 2)
A["files_with_high_plus"] = worst["critical"] + worst["high"]
A["files_with_high_plus_pct"] = pct(worst["critical"] + worst["high"], len(parsed), 2)
A["low_by_rule"] = Counter(x["rule_id"] for v in parsed.values() for x in v["findings"] if x["severity"] == "low")
out["A_overview"] = A

# ---- B. skipped -------------------------------------------------------------
B = {"by_class": Counter(), "by_tier": Counter(), "clean_by_tier": Counter()}
for v in prevl.values():
    if v["status"] == "skipped":
        B["by_class"]["v1" if "Compose v1" in v["skip"] else "fragment" if "fragment" in v["skip"] else "other"] += 1
        B["by_tier"][v["tier"]] += 1
for v in parsed.values():
    if not v["findings"]:
        B["clean_by_tier"][v["tier"]] += 1
B["skip_pct_of_prevalence"] = pct(A["skipped"], len(prevl))
# v1 share by age, prevalence tiers, all dated files
v1age = defaultdict(lambda: [0, 0])
for v in prevl.values():
    if v["age"] is None:
        continue
    b = ">=5y" if v["age"] >= 1825 else "<1y" if v["age"] < 365 else "mid"
    v1age[b][1] += 1
    if v["status"] == "skipped" and "Compose v1" in v["skip"]:
        v1age[b][0] += 1
B["v1_share_by_age"] = {k: (a, n, pct(a, n)) for k, (a, n) in v1age.items()}
skipage = defaultdict(lambda: [0, 0])
for v in prevl.values():
    if v["age"] is None:
        continue
    b = ">=5y" if v["age"] >= 1825 else "<1y" if v["age"] < 365 else "mid"
    skipage[b][1] += 1
    if v["status"] == "skipped":
        skipage[b][0] += 1
B["skip_share_by_age"] = {k: (a, n, pct(a, n)) for k, (a, n) in skipage.items()}
# never-linted chart: (skipped+parse_err)/total per tier
B["never_linted_pct"] = {}
for t in TIERS:
    tt = [v for v in prevl.values() if v["tier"] == t]
    B["never_linted_pct"][t] = pct(sum(1 for v in tt if v["status"] != "parsed"), len(tt))
out["B_skipped"] = B

# ---- C/D. per tier ----------------------------------------------------------
C = {}
for t in TIERS:
    tt = {h: v for h, v in prevl.items() if v["tier"] == t}
    tp = {h: v for h, v in tt.items() if v["status"] == "parsed"}
    nf = sum(len(v["findings"]) for v in tp.values())
    ns = sum(svc[h] or 0 for h in tp)
    sock_svcs = len({(h, x["service"]) for h, v in tp.items() for x in v["findings"] if x["rule_id"] == "CL-0001"})
    crit = sum(1 for v in tp.values() if any(x["severity"] == "critical" for x in v["findings"]))
    hp = sum(1 for v in tp.values() if any(x["severity"] in ("critical", "high") for x in v["findings"]))
    sockf = sum(1 for v in tp.values() if "CL-0001" in v["rids"])
    C[t] = {
        "total": len(tt), "parsed": len(tp),
        "skipped": sum(1 for v in tt.values() if v["status"] == "skipped"),
        "parse_err": sum(1 for v in tt.values() if v["status"] == "parse_error"),
        "with_findings": sum(1 for v in tp.values() if v["findings"]),
        "clean": sum(1 for v in tp.values() if not v["findings"]),
        "rate": pct(sum(1 for v in tp.values() if v["findings"]), len(tp), 2),
        "findings": nf, "findings_per_parsed": round(nf / len(tp), 2),
        "repos": len({v["repo"] for v in tt.values()}),
        "services": ns, "svc_per_file": round(ns / len(tp), 2),
        "findings_per_service": round(nf / ns, 2),
        "files_critical_pct": pct(crit, len(tp)), "files_high_plus_pct": pct(hp, len(tp)),
        "socket_files_pct": pct(sockf, len(tp)), "socket_files": sockf,
        "socket_services": sock_svcs, "socket_services_pct": pct(sock_svcs, ns),
        "parse_err_pct_of_total": pct(sum(1 for v in tt.values() if v["status"] == "parse_error"), len(tt)),
    }
out["C_tiers"] = C
out["C_repos_prevalence"] = len({v["repo"] for v in prevl.values()})
all_svc = sum(svc[h] or 0 for h in parsed)
out["C_all"] = {"services": all_svc, "findings_per_service": round(total / all_svc, 2),
                "svc_per_file": round(all_svc / len(parsed), 2),
                "socket_files": sum(1 for v in parsed.values() if "CL-0001" in v["rids"]),
                "socket_files_pct": pct(sum(1 for v in parsed.values() if "CL-0001" in v["rids"]), len(parsed), 2)}
out["C_all"]["popular_vs_longtail_socket_service_ratio"] = round(
    C["popular"]["socket_services_pct"] / C["longtail"]["socket_services_pct"], 2)

# ---- E. rules ---------------------------------------------------------------
hits = Counter(x["rule_id"] for v in parsed.values() for x in v["findings"])
files = Counter(r for v in parsed.values() for r in v["rids"])
rsev = {}
for v in parsed.values():
    for x in v["findings"]:
        rsev.setdefault(x["rule_id"], set()).add(x["severity"])
E = {r: {"sev": sorted(rsev[r]), "hits": hits[r], "files": files[r], "share": pct(files[r], len(parsed), 2)}
     for r in sorted(files, key=lambda r: -files[r])}
out["E_rules"] = E
top10 = sum(n for _, n in hits.most_common(10))
out["E_top10"] = {"rules": [r for r, _ in hits.most_common(10)], "share_of_findings": pct(top10, total, 2)}
allr = Counter(x["rule_id"] for v in recs.values() for x in v["findings"])
out["E_rules_firing_whole_corpus"] = len(allr)
out["E_rules_firing_prevalence"] = len(hits)
out["E_rule_hits_whole_corpus"] = dict(sorted(allr.items()))
cred = sum(1 for v in parsed.values() if v["rids"] & {"CL-0020", "CL-0021"})
FOUR = {"CL-0003", "CL-0006", "CL-0007", "CL-0026"}
none_of_four = sum(1 for v in parsed.values() if FOUR <= v["rids"])
out["E_all_four_flags_missing"] = (none_of_four, len(parsed), pct(none_of_four, len(parsed), 2))
out["E_cred_fullfile"] = (cred, len(parsed), pct(cred, len(parsed), 2))
ports_full = sum(1 for v in parsed.values() if "CL-0005" in v["rids"])
out["E_ports_fullfile_pct"] = pct(ports_full, len(parsed))
# top four by tier (does the same four lead every tier?)
out["E_top4_by_tier"] = {}
for t in TIERS:
    c = Counter(r for v in parsed.values() if v["tier"] == t for r in v["rids"])
    n = sum(1 for v in parsed.values() if v["tier"] == t)
    out["E_top4_by_tier"][t] = [(r, pct(k, n)) for r, k in c.most_common(5)]

# ---- F. overlay -------------------------------------------------------------
ov = {h: v for h, v in recs.items() if v["tier"] == "overlay"}
ovp = {h: v for h, v in ov.items() if v["status"] == "parsed"}
F = {"total": len(ov), "status": Counter(v["status"] for v in ov.values()),
     "parsed_pct": pct(len(ovp), len(ov)),
     "clean": sum(1 for v in ovp.values() if not v["findings"])}
osvc = sum(svc[h] or 0 for h in ovp)
onf = sum(len(v["findings"]) for v in ovp.values())
F["svc_per_file"] = round(osvc / len(ovp), 2)
F["findings_per_service"] = round(onf / osvc, 2)
F["ports_pct"] = pct(sum(1 for v in ovp.values() if "CL-0005" in v["rids"]), len(ovp))
F["cred_pct"] = pct(sum(1 for v in ovp.values() if v["rids"] & {"CL-0020", "CL-0021"}), len(ovp))
var = defaultdict(lambda: [0, 0, 0])
for v in ovp.values():
    parts = Path(v["path"]).name.split(".")
    k = parts[-2] if len(parts) >= 3 else "?"
    var[k][1] += 1
    if v["rids"] & {"CL-0020", "CL-0021"}:
        var[k][0] += 1
    if "CL-0005" in v["rids"]:
        var[k][2] += 1
F["variants"] = {k: {"files": n, "cred_pct": pct(c, n), "ports_pct": pct(p, n)} for k, (c, n, p) in sorted(var.items(), key=lambda kv: -kv[1][1])}
dated = [v["age"] for v in ov.values() if v["age"] is not None]
F["age_all"] = {"dated": len(dated), "<1y": pct(sum(1 for d in dated if d < 365), len(dated)),
                "<3y": pct(sum(1 for d in dated if d < 1095), len(dated))}
F["skip_classes"] = Counter("v1" if "Compose v1" in v["skip"] else "fragment" for v in ov.values() if v["status"] == "skipped")
out["F_overlay"] = F

# ---- G. age -----------------------------------------------------------------
G = {}
agg = defaultdict(lambda: [0, 0, 0])
for t in TIERS:
    row = defaultdict(lambda: [0, 0, 0])
    for h, v in parsed.items():
        if v["tier"] != t or v["age"] is None or svc[h] is None:
            continue
        b = bucket3(v["age"])
        for tgt in (row[b], agg[b]):
            tgt[0] += svc[h]
            tgt[1] += len(v["findings"])
            tgt[2] += 1
    G[t] = {b: (round(f / s, 2) if s else None, n) for b, (s, f, n) in row.items()}
G["all"] = {b: (round(f / s, 2), n) for b, (s, f, n) in agg.items()}
dall = [v["age"] for v in recs.values() if v["age"] is not None]
dprev = [v["age"] for v in prevl.values() if v["age"] is not None]
dpars = [v["age"] for v in parsed.values() if v["age"] is not None]
for name, d in (("whole_corpus", dall), ("prevalence", dprev), ("prevalence_parsed", dpars)):
    G["age_mix_" + name] = {"dated": len(d), "<1y": pct(sum(1 for x in d if x < 365), len(d)),
                            "<3y": pct(sum(1 for x in d if x < 1095), len(d)),
                            ">=5y": pct(sum(1 for x in d if x >= 1825), len(d))}
G["dated_coverage_pct"] = pct(len(dall), len(recs), 2)
fresh = {h for h, v in recs.items() if order[h] >= FRESH_START and v["tier"] == "longtail"}
shallow = {h for h, v in recs.items() if order[h] < SHALLOW_END and v["tier"] == "longtail"}
for name, s in (("fresh_longtail", fresh), ("shallow_longtail", shallow)):
    d = [recs[h]["age"] for h in s if recs[h]["age"] is not None]
    G[name] = {"files": len(s), ">=5y_pct": pct(sum(1 for x in d if x >= 1825), len(d)),
               "v1": sum(1 for h in s if "Compose v1" in recs[h]["skip"])}
out["G_age"] = G

# ---- I. parse errors --------------------------------------------------------
def pclass(stderr):
    first = stderr.splitlines()[0] if stderr else ""
    for label, pat in (
        ("missing-services-key", r"missing 'services' key"),
        ("services-not-mapping", r"'services' must be a mapping"),
        ("service-not-mapping", r"service '[^']+' must be a mapping"),
        ("empty-file", r"file is empty"),
        ("top-level-not-mapping", r"expected a YAML mapping at the top level"),
        ("invalid-yaml", r"Invalid YAML:"),
    ):
        if re.search(pat, first):
            return label
    low = stderr.lower()
    if "include" in low:
        return "include"
    if "extends" in low:
        return "extends"
    return "other"

I = {"prevalence": Counter(), "all": Counter()}
for v in recs.values():
    if v["status"] == "parse_error":
        c = pclass(v["stderr"])
        I["all"][c] += 1
        if v["tier"] not in EXCL:
            I["prevalence"][c] += 1
I["prevalence_total"] = sum(I["prevalence"].values())
I["prevalence_pct"] = pct(I["prevalence_total"], len(prevl))
out["I_parse_errors"] = I

# ---- J. bootstrap (cluster over repos) --------------------------------------
def boot(tier, stat, n=2000, seed=20260827):
    by_repo = defaultdict(list)
    for h, v in parsed.items():
        if v["tier"] == tier:
            by_repo[v["repo"]].append(h)
    repos = sorted(by_repo)
    rng = random.Random(seed)
    vals = []
    for _ in range(n):
        sample = [h for r in rng.choices(repos, k=len(repos)) for h in by_repo[r]]
        vals.append(stat(sample))
    vals.sort()
    return (round(vals[int(0.025 * n)], 2), round(vals[int(0.975 * n) - 1], 2))

J = {}
wf = lambda s: 100 * sum(1 for h in s if parsed[h]["findings"]) / len(s)
sock_n = {h: len({x["service"] for x in v["findings"] if x["rule_id"] == "CL-0001"})
          for h, v in recs.items()}
def sockrate(s):
    # per-file counts, so a repo drawn twice counts twice on both sides
    return 100 * sum(sock_n[h] for h in s) / sum(svc[h] or 0 for h in s)
fps = lambda s: sum(len(parsed[h]["findings"]) for h in s) / sum(svc[h] or 0 for h in s)
for t in TIERS:
    J[t] = {"with_findings_ci": boot(t, wf), "socket_per_service_ci": boot(t, sockrate),
            "findings_per_service_ci": boot(t, fps)}
out["J_bootstrap"] = J

# ---- K. replication: fresh longtail ----------------------------------------
fp = [h for h in fresh if recs[h]["status"] == "parsed"]
K = {"files": len(fresh), "repos": len({recs[h]["repo"] for h in fresh}), "parsed": len(fp),
     "with_findings_pct": pct(sum(1 for h in fp if recs[h]["findings"]), len(fp)),
     "findings_per_service": round(sum(len(recs[h]["findings"]) for h in fp) / sum(svc[h] or 0 for h in fp), 2)}
row = defaultdict(lambda: [0, 0])
for h in fp:
    if recs[h]["age"] is None:
        continue
    b = bucket3(recs[h]["age"])
    row[b][0] += svc[h] or 0
    row[b][1] += len(recs[h]["findings"])
K["by_age"] = {b: round(f / s, 2) for b, (s, f) in row.items()}
sp = [h for h in shallow if recs[h]["status"] == "parsed"]
K["prior_lane"] = {"files": len(shallow), "parsed": len(sp),
                   "with_findings_pct": pct(sum(1 for h in sp if recs[h]["findings"]), len(sp)),
                   "findings_per_service": round(sum(len(recs[h]["findings"]) for h in sp) / sum(svc[h] or 0 for h in sp), 2)}
K["post_freeze_tiers_deep_sweep"] = Counter(recs[h]["tier"] for h in recs if order[h] >= FRESH_START)
K["overlay_sweep_tiers"] = Counter(recs[h]["tier"] for h in recs if SHALLOW_END <= order[h] < FRESH_START)
K["fresh_socket_per_service_pct"] = round(sockrate(fp), 2)
K["prior_socket_per_service_pct"] = round(sockrate(sp), 2)
out["K_replication"] = K

def norm(o):
    if isinstance(o, dict):
        return {str(k): norm(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [norm(x) for x in o]
    return o

# ---- same-files delta against a base run -----------------------------------
if base_dir is not None:
    base = {}
    for line in (base_dir / "results.jsonl").open():
        r = json.loads(line)
        base[r["content_hash"]] = r
    D = {"base": json.loads((base_dir / "meta.json").read_text())["compose_lint_version"],
         "status_moves": Counter(), "flips": 0, "files_changed": 0,
         "files_changed_prevalence": 0, "added": Counter(), "removed": Counter(),
         "added_prevalence": Counter(), "removed_prevalence": Counter(),
         "added_on_hooks": Counter()}
    hook = re.compile(r"\.(pre_start|post_start|pre_stop|post_stop)\[")
    for h, v in recs.items():
        b = base[h]
        bst = status(b)
        D["status_moves"][f"{bst} -> {v['status']}"] += 1
        if bst != "parsed" or v["status"] != "parsed":
            continue
        bf = b["lint"]["findings"]
        if bool(bf) != bool(v["findings"]):
            D["flips"] += 1
        old = Counter((x["rule_id"], x.get("service")) for x in bf)
        new = Counter((x["rule_id"], x.get("service")) for x in v["findings"])
        add, rem = new - old, old - new
        prevalence = v["tier"] not in EXCL
        if add or rem:
            D["files_changed"] += 1
            D["files_changed_prevalence"] += prevalence
        for (rid, service), k in add.items():
            D["added"][rid] += k
            D["added_prevalence"][rid] += k * prevalence
            if hook.search(service or ""):
                D["added_on_hooks"][rid] += k
        for (rid, _), k in rem.items():
            D["removed"][rid] += k
            D["removed_prevalence"][rid] += k * prevalence
    out["delta_vs_base"] = D

json.dump(norm(out), sys.stdout, indent=1)
print()
