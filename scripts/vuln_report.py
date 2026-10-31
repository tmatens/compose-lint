#!/usr/bin/env python3
"""Build the rolling "fixable vulnerabilities" issue body.

Consumes a pip-audit JSON report and, optionally, a Docker Scout SARIF
report and a zizmor JSON report, and emits a Markdown body plus a
has-findings flag.

Design notes
------------
* **Fixability, not severity, decides whether this pages.** An advisory
  with an available fix lands in the gating tables at any severity; one
  with no fix is listed in a collapsed section that does not open or
  close the issue.
* **No suppressions are applied here.** The report deliberately runs
  pip-audit without ``--ignore-vuln`` so that an advisory suppressed in
  ``ci.yml``/``publish.yml`` still shows up. A suppression whose stated
  justification has gone stale (see the tuf/``GHSA-qp9x-wp8f-qgjj``
  case) is otherwise invisible to every scanner at once.
* **Missing or unparseable input is a hard error**, never an implicit
  "all clear". A reporting job that silently reports clean is worse
  than no reporting job.
* **The OpenVEX document is checked for completeness, not the image.**
  Scanners match pip CVEs against the pip ``.dist-info`` the image keeps,
  so a pip advisory whose range covers a pip version that any published
  tag retains produces a finding on that tag until a ``not_affected``
  statement covers it. Only ``latest`` is ever scanned, and it upgrades
  pip before stripping it, so an advisory published and fixed between two
  releases never reaches a scanner here (#1040). The report therefore
  diffs pip's advisory list from OSV against the statement names in the
  VEX file; a missing ID is a gap to document, not a vulnerability to fix.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

MARKER = "<!-- vuln-report:managed -->"


class ReportError(RuntimeError):
    """Input was missing or did not have the expected shape."""


def _load_json(path: Path, what: str) -> Any:
    if not path.is_file():
        raise ReportError(f"{what}: {path} does not exist")
    if path.stat().st_size == 0:
        raise ReportError(f"{what}: {path} is empty")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReportError(f"{what}: {path} is not valid JSON: {exc}") from exc


def parse_pip_audit(path: Path) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Return (fixable, unfixable) rows from a pip-audit JSON report."""
    data = _load_json(path, "pip-audit report")
    if not isinstance(data, dict) or "dependencies" not in data:
        raise ReportError("pip-audit report has no 'dependencies' key; shape changed?")

    fixable: list[dict[str, str]] = []
    unfixable: list[dict[str, str]] = []
    for dep in data["dependencies"]:
        if dep.get("skip_reason"):
            continue
        for vuln in dep.get("vulns") or []:
            fixes = [str(v) for v in (vuln.get("fix_versions") or [])]
            row = {
                "id": str(vuln.get("id", "?")),
                "package": str(dep.get("name", "?")),
                "installed": str(dep.get("version", "?")),
                "fixed_in": ", ".join(fixes) if fixes else "—",
            }
            (fixable if fixes else unfixable).append(row)

    fixable.sort(key=lambda r: (r["package"], r["id"]))
    unfixable.sort(key=lambda r: (r["package"], r["id"]))
    return fixable, unfixable


def _severity_band(score: str) -> str:
    """Map a SARIF ``security-severity`` CVSS score to a band name."""
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    if value > 0.0:
        return "low"
    return "none"


def parse_scout_sarif(path: Path) -> list[dict[str, str]]:
    """Return rows for image CVEs from a Docker Scout SARIF report.

    Scout is invoked with ``only-fixed: true``, so every result here is
    by definition fixable and no fix-version filtering is applied.
    """
    data = _load_json(path, "Scout SARIF report")
    runs = data.get("runs") if isinstance(data, dict) else None
    if not isinstance(runs, list):
        raise ReportError("Scout SARIF has no 'runs' list; shape changed?")

    rows: list[dict[str, str]] = []
    for run in runs:
        driver = (run.get("tool") or {}).get("driver") or {}
        rules = {r.get("id"): r for r in (driver.get("rules") or []) if r.get("id")}
        for result in run.get("results") or []:
            rule_id = result.get("ruleId") or "?"
            rule = rules.get(rule_id, {})
            props = rule.get("properties") or {}
            detail = (
                (rule.get("shortDescription") or {}).get("text")
                or (result.get("message") or {}).get("text")
                or ""
            )
            rows.append(
                {
                    "id": str(rule_id),
                    "severity": _severity_band(props.get("security-severity", "")),
                    "detail": " ".join(str(detail).split())[:160] or "—",
                }
            )

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows.sort(key=lambda r: (order.get(r["severity"], 9), r["id"]))
    return rows


def parse_vex_ids(path: Path) -> set[str]:
    """Return every vulnerability identifier the OpenVEX document names.

    A statement's ``vulnerability.name`` plus any ``aliases`` it lists, so
    an advisory is covered whichever identifier the document chose.
    """
    data = _load_json(path, "OpenVEX document")
    statements = data.get("statements") if isinstance(data, dict) else None
    if not isinstance(statements, list):
        raise ReportError("OpenVEX document has no 'statements' list; shape changed?")
    ids: set[str] = set()
    for statement in statements:
        vuln = statement.get("vulnerability") if isinstance(statement, dict) else None
        if not isinstance(vuln, dict) or not vuln.get("name"):
            raise ReportError("OpenVEX statement without a vulnerability.name")
        ids.add(str(vuln["name"]))
        ids.update(str(alias) for alias in (vuln.get("aliases") or []))
    return ids


ZIZMOR_AUDIT = "known-vulnerable-actions"


def _zizmor_where(location: dict[str, Any]) -> tuple[str, str]:
    """Return ``(where, version comment)`` for one zizmor finding location."""
    symbolic = location.get("symbolic") or {}
    concrete = location.get("concrete") or {}
    key = symbolic.get("key") or {}
    local = key.get("Local") if isinstance(key, dict) else None
    path = str((local or {}).get("verbatim_path") or "?").removeprefix("./")
    row = ((concrete.get("location") or {}).get("start_point") or {}).get("row")
    where = f"{path}:{row + 1}" if isinstance(row, int) else path
    comments = concrete.get("comments") or []
    comment = str(comments[0]).lstrip("#").strip() if comments else ""
    return where, comment


def parse_zizmor_actions(
    path: Path,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Return (fixable, unfixable) rows for actions with a known advisory.

    Reads ``zizmor --format json`` output and keeps the
    ``known-vulnerable-actions`` audit only: the rest of zizmor is ci.yml's
    gate, which runs when a workflow changes. An advisory against an
    unchanged pin arrives with time, not with a diff, so nothing else sees it.
    A finding zizmor offers an upgrade for is fixable. Findings the config
    ignores are kept, for the same anti-rot reason pip-audit runs
    unsuppressed. One row per advisory and action, listing every use.
    """
    data = _load_json(path, "zizmor report")
    if not isinstance(data, list):
        raise ReportError("zizmor report is not a list of findings; shape changed?")

    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in data:
        if not isinstance(finding, dict) or "ident" not in finding:
            raise ReportError("zizmor finding without an 'ident'; shape changed?")
        if finding["ident"] != ZIZMOR_AUDIT:
            continue
        locations = finding.get("locations") or []
        primary = next(
            (
                loc
                for loc in locations
                if (loc.get("symbolic") or {}).get("kind") == "Primary"
            ),
            locations[0] if locations else {},
        )
        advisory = str((primary.get("symbolic") or {}).get("annotation") or "?")
        feature = str((primary.get("concrete") or {}).get("feature") or "")
        action = feature.removeprefix("uses:").strip().split("@", 1)[0] or "?"
        where, pinned = _zizmor_where(primary)
        fixes = [str(f.get("title", "")) for f in finding.get("fixes") or []]
        row = grouped.setdefault(
            (advisory, action),
            {
                "id": advisory,
                "action": action,
                "pinned": pinned or "?",
                "fix": "; ".join(f for f in fixes if f) or "—",
                "where": [],
            },
        )
        row["where"].append(where)

    fixable: list[dict[str, str]] = []
    unfixable: list[dict[str, str]] = []
    for row in grouped.values():
        out = {**row, "where": ", ".join(sorted(set(row["where"])))}
        (unfixable if out["fix"] == "—" else fixable).append(out)
    fixable.sort(key=lambda r: (r["action"], r["id"]))
    unfixable.sort(key=lambda r: (r["action"], r["id"]))
    return fixable, unfixable


def _fixed_versions(vuln: dict[str, Any], package: str) -> list[str]:
    """Fix versions for ``package`` from its ECOSYSTEM (and SEMVER) ranges.

    GIT ranges carry commit hashes as their ``fixed`` events, not versions.
    The first live run listed CVE-2019-20916 as a gap because its GIT range's
    hash could not be ruled out against the floor; only version ranges can.
    """
    fixed: list[str] = []
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if str(pkg.get("name", "")).lower() != package.lower():
            continue
        for rng in affected.get("ranges") or []:
            if str(rng.get("type", "")).upper() not in {"ECOSYSTEM", "SEMVER"}:
                continue
            for event in rng.get("events") or []:
                if "fixed" in event:
                    fixed.append(str(event["fixed"]))
    return fixed


def _above_floor(fixed: list[str], floor: Version) -> bool:
    """True when some fix lands above the floor, so a retained pip could match."""
    for version in fixed:
        try:
            if Version(version) > floor:
                return True
        except InvalidVersion:
            # An unparseable fix version cannot be ruled out; keep the advisory.
            return True
    return False


def parse_osv_gaps(
    path: Path, vex_ids: set[str], package: str, floor: str
) -> tuple[list[dict[str, str]], int]:
    """Return (gaps, considered) from an OSV ``/v1/query`` response.

    ``gaps`` are advisories for ``package`` that no VEX statement names, by
    any of their identifiers. Advisories whose every fix is at or below
    ``floor`` are out of scope: no published image retains a pip that old,
    so no scanner can match them. An advisory with no fix at all is kept.
    ``considered`` counts the in-scope advisories, so a clean report can
    say what it compared.
    """
    data = _load_json(path, "OSV advisory list")
    if not isinstance(data, dict) or not isinstance(data.get("vulns"), list):
        raise ReportError(
            "OSV response has no 'vulns' list; query failed or shape changed?"
        )
    if data.get("next_page_token"):
        raise ReportError(
            "OSV response is paginated (next_page_token present); the fetch step "
            "reads one page, so the comparison would be against a partial list"
        )
    vulns = data["vulns"]
    if not vulns:
        raise ReportError(
            f"OSV lists no advisories at all for {package}; a query that returns "
            "nothing for a package with known CVEs is broken, not clean"
        )
    try:
        floor_version = Version(floor)
    except InvalidVersion as exc:
        raise ReportError(f"--pip-floor {floor!r} is not a version") from exc

    gaps: list[dict[str, str]] = []
    considered = 0
    for vuln in vulns:
        if not isinstance(vuln, dict) or vuln.get("withdrawn"):
            continue
        ids = {str(vuln.get("id", ""))} | {str(a) for a in (vuln.get("aliases") or [])}
        ids.discard("")
        if not ids:
            raise ReportError("OSV advisory without an id")
        fixed = _fixed_versions(vuln, package)
        if fixed and not _above_floor(fixed, floor_version):
            continue
        considered += 1
        if ids & vex_ids:
            continue
        cve = sorted(i for i in ids if i.startswith("CVE-"))
        gaps.append(
            {
                "id": cve[0] if cve else sorted(ids)[0],
                "published": str(vuln.get("published", ""))[:10] or "—",
                "fixed_in": ", ".join(sorted(fixed, key=_sort_version))
                if fixed
                else "—",
                "summary": _summary(vuln),
            }
        )
    gaps.sort(key=lambda r: (r["published"], r["id"]))
    return gaps, considered


def _summary(vuln: dict[str, Any]) -> str:
    """OSV's ``summary`` when present, else the first sentence of ``details``.

    PyPI-sourced pip advisories often carry only ``details``; the first live
    run rendered an em dash where a reader needed to know what the CVE was.
    """
    text = str(vuln.get("summary") or "").strip()
    if not text:
        details = str(vuln.get("details") or "").strip()
        text = details.split("\n", 1)[0]
    text = " ".join(text.split())
    return (text[:117] + "...") if len(text) > 120 else (text or "—")


def _sort_version(version: str) -> tuple[int, Any]:
    try:
        return (0, Version(version))
    except InvalidVersion:
        return (1, version)


def _table(headers: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |"]
    out.append("|" + "|".join(["---"] * len(headers)) + "|")
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def build_body(
    py_fixable: list[dict[str, str]],
    py_unfixable: list[dict[str, str]],
    img_fixable: list[dict[str, str]],
    image: str,
    run_url: str,
    vex: tuple[Path, str, list[dict[str, str]], int, str] | None = None,
    actions: tuple[list[dict[str, str]], list[dict[str, str]]] | None = None,
) -> str:
    """Render the issue body.

    ``vex`` is ``(vex_path, package, gaps, considered, floor)`` when the
    OpenVEX completeness check ran, else ``None`` and the section is omitted.
    ``actions`` is ``(fixable, unfixable)`` from the zizmor report, else
    ``None`` and that section is omitted too.
    """
    act_fixable, act_unfixable = actions if actions else ([], [])
    total = len(py_fixable) + len(img_fixable) + len(act_fixable)
    gaps = vex[2] if vex else []
    noun = "vulnerability" if total == 1 else "vulnerabilities"
    tail = (
        " — every advisory below has a fix available, at any severity."
        if total
        else " — nothing to fix right now."
    )
    headline = f"**{total} fixable {noun}**{tail}"
    if gaps:
        gap_noun = "gap" if len(gaps) == 1 else "gaps"
        headline += (
            f" **{len(gaps)} OpenVEX {gap_noun}** — pip advisories no statement "
            "covers yet."
        )
    parts = [
        MARKER,
        headline,
        "",
        (
            "This issue is maintained automatically: the body is rewritten on "
            "each run and the issue **closes itself** when the fixable list and "
            "the OpenVEX gap list are both empty. An open issue therefore means "
            "there is something to do right now."
        ),
        "",
    ]

    parts.append("## Python dependencies (`requirements-dev.lock`)")
    parts.append("")
    if py_fixable:
        parts.append(
            _table(
                ["Advisory", "Package", "Installed", "Fixed in"],
                [
                    [f"`{r['id']}`", r["package"], r["installed"], r["fixed_in"]]
                    for r in py_fixable
                ],
            )
        )
        parts.append("")
        parts.append(
            "Bump with "
            "`uv pip compile ... --upgrade-package <name>` for a minimal diff "
            "(see CLAUDE.md → Regenerating lockfiles)."
        )
    else:
        parts.append("None. ✅")
    parts.append("")

    parts.append(f"## Published image (`{image}`)")
    parts.append("")
    if img_fixable:
        parts.append(
            _table(
                ["CVE", "Severity", "Detail"],
                [[f"`{r['id']}`", r["severity"], r["detail"]] for r in img_fixable],
            )
        )
        parts.append("")
        parts.append(
            "Image CVEs are usually cleared by bumping the base image digest "
            "in `Dockerfile` (Renovate proposes these) and cutting a release."
        )
    else:
        parts.append("None. ✅")
    parts.append("")

    if actions is not None:
        parts.append("## GitHub Actions (`.github/`, `action.yml`)")
        parts.append("")
        if act_fixable:
            parts.append(
                _table(
                    ["Advisory", "Action", "Pinned", "Fix", "Used at"],
                    [
                        [
                            f"`{r['id']}`",
                            f"`{r['action']}`",
                            r["pinned"],
                            r["fix"],
                            r["where"],
                        ]
                        for r in act_fixable
                    ],
                )
            )
            parts.append("")
            parts.append(
                "Move every use to the fixed release's commit SHA, tag in the "
                "trailing comment. Renovate proposes these, but it can hold one "
                "for a schedule or a minimum release age; an advisory is a "
                "reason not to wait for it."
            )
        else:
            parts.append("None. ✅")
        if act_unfixable:
            parts.append("")
            parts.append(
                "Known, no fix available — does not gate this issue: "
                + ", ".join(f"`{r['id']}` (`{r['action']}`)" for r in act_unfixable)
                + "."
            )
        parts.append("")

    if vex is not None:
        vex_path, package, gaps, considered, floor = vex
        parts.append(f"## OpenVEX document (`{vex_path}`)")
        parts.append("")
        if gaps:
            parts.append(
                _table(
                    ["Advisory", "Published", "Fixed in", "Summary"],
                    [
                        [f"`{r['id']}`", r["published"], r["fixed_in"], r["summary"]]
                        for r in gaps
                    ],
                )
            )
            parts.append("")
            parts.append(
                f"These {package} advisories affect a {package} version some "
                "published tag still carries in its metadata, and no statement "
                "names them. Scanners will report them against that tag until one "
                "does. Add a `not_affected` / `vulnerable_code_not_present` "
                "statement once you have confirmed the vulnerable code lives in "
                f"the stripped {package} package (docs/RELEASING.md, OpenVEX item); "
                "if it is reachable, fix it instead. Bump `version` and "
                "`timestamp` in the document."
            )
        else:
            parts.append(
                f"Complete. ✅ Every {package} advisory in OSV with a fix above "
                f"{package} {floor} ({considered}) is named by a statement."
            )
        parts.append("")

    if py_unfixable:
        parts.append(
            f"<details><summary>Known, no fix available "
            f"({len(py_unfixable)}) — does not gate this issue</summary>"
        )
        parts.append("")
        parts.append(
            _table(
                ["Advisory", "Package", "Installed"],
                [[f"`{r['id']}`", r["package"], r["installed"]] for r in py_unfixable],
            )
        )
        parts.append("")
        parts.append("</details>")
        parts.append("")

    parts += [
        "---",
        "",
        (
            "This report applies **no `--ignore-vuln` suppressions**, so an "
            "advisory suppressed in `ci.yml` or `publish.yml` still appears "
            "here. That is deliberate — a suppression whose justification has "
            "gone stale is otherwise invisible to pip-audit (it is filtered by "
            "ID) *and* to Renovate (the pin is already satisfiable) at the same "
            "time."
        ),
        "",
        f"[Workflow run]({run_url})" if run_url else "",
    ]
    return "\n".join(p for p in parts if p is not None).rstrip() + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pip-audit", type=Path, required=True)
    ap.add_argument("--scout-sarif", type=Path)
    ap.add_argument("--image", default="composelint/compose-lint:latest")
    ap.add_argument("--run-url", default="")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument(
        "--vex",
        type=Path,
        help="OpenVEX document whose statements must cover every in-scope advisory",
    )
    ap.add_argument(
        "--osv",
        type=Path,
        help="OSV /v1/query response for --osv-package (one page, no token)",
    )
    ap.add_argument("--osv-package", default="pip")
    ap.add_argument(
        "--zizmor",
        type=Path,
        help="zizmor --format json report, from an online run",
    )
    ap.add_argument(
        "--pip-floor",
        default="0",
        help="advisories whose every fix is at or below this version are out of scope",
    )
    args = ap.parse_args()
    if (args.vex is None) != (args.osv is None):
        ap.error("--vex and --osv must be given together")

    vex: tuple[Path, str, list[dict[str, str]], int, str] | None = None
    actions: tuple[list[dict[str, str]], list[dict[str, str]]] | None = None
    try:
        py_fixable, py_unfixable = parse_pip_audit(args.pip_audit)
        img_fixable = parse_scout_sarif(args.scout_sarif) if args.scout_sarif else []
        if args.vex is not None:
            gaps, considered = parse_osv_gaps(
                args.osv, parse_vex_ids(args.vex), args.osv_package, args.pip_floor
            )
            vex = (args.vex, args.osv_package, gaps, considered, args.pip_floor)
        if args.zizmor is not None:
            actions = parse_zizmor_actions(args.zizmor)
    except ReportError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    body = build_body(
        py_fixable, py_unfixable, img_fixable, args.image, args.run_url, vex, actions
    )
    args.out.write_text(body, encoding="utf-8")

    act_fixable = actions[0] if actions else []
    total = len(py_fixable) + len(img_fixable) + len(act_fixable)
    gap_count = len(vex[2]) if vex else 0
    print(
        f"fixable: python={len(py_fixable)} image={len(img_fixable)} "
        f"actions={len(act_fixable)} "
        f"total={total}; unfixable (informational): {len(py_unfixable)}; "
        f"vex_gaps={gap_count}"
    )

    title = f"Fixable vulnerabilities ({total})"
    if gap_count:
        title += f", OpenVEX gaps ({gap_count})"
    if step_output := os.environ.get("GITHUB_OUTPUT"):
        with open(step_output, "a", encoding="utf-8") as fh:
            fh.write(f"count={total}\n")
            fh.write(f"gaps={gap_count}\n")
            fh.write(f"title={title}\n")
            fh.write(f"has_findings={'true' if total or gap_count else 'false'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
