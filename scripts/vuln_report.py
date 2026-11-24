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
* **An image finding with no fix still needs a decision, once.** A second
  Scout scan, without ``only-fixed`` and with the OpenVEX document applied,
  lists what the published image is still reported for. Each of those is
  either fixable (the table above), accepted as open in
  ``.vex/open-findings.json``, or undecided. An undecided one gates this
  issue only after it has gone unfixed for ``--min-age-days`` since
  publication, because most are fixed by a base image update before then,
  and only when the scheduled Scout scan's code-scanning alerts report it
  too, because Scout's advisory data changes between scans. The same two
  scans must both have dropped an accepted entry before it is called stale.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, date, datetime
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


_PURL = re.compile(r"Package\s*:\s*pkg:[^/\s]+/(?:[^/\s@]+/)*([^/\s@?]+)")


def _package_label(message: str) -> str:
    """Package name from the ``Package :pkg:...`` line of a Scout result."""
    match = _PURL.search(message)
    return match.group(1) if match else "—"


def parse_scout_sarif(path: Path) -> list[dict[str, str]]:
    """Return rows for image CVEs from a Docker Scout SARIF report.

    No fix-version filtering is applied: the caller chooses the scan. With
    ``only-fixed: true`` every result is by definition fixable; without it
    the results are everything the image is reported for.
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
                    "package": _package_label(
                        str((result.get("message") or {}).get("text") or "")
                    ),
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


def parse_open_findings(path: Path) -> list[dict[str, str]]:
    """Return the accepted open findings from ``.vex/open-findings.json``.

    Each entry needs an ``id``, a ``package`` and a ``reason``: an entry
    with no reason is a suppression, which is what this list must not be.
    """
    data = _load_json(path, "open findings list")
    findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(findings, list):
        raise ReportError("open findings list has no 'findings' list; shape changed?")
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for entry in findings:
        if not isinstance(entry, dict):
            raise ReportError("open findings entry is not an object")
        row = {k: str(entry.get(k) or "").strip() for k in ("id", "package", "reason")}
        missing = [k for k, v in row.items() if not v]
        if missing:
            raise ReportError(
                f"open findings entry {row['id'] or '?'} lacks {', '.join(missing)}"
            )
        if row["id"] in seen:
            raise ReportError(f"open findings list names {row['id']} twice")
        seen.add(row["id"])
        rows.append(row)
    return rows


def parse_alert_ids(path: Path) -> set[str]:
    """Return the rule ids of the scheduled Scout scan's open alerts.

    The workflow writes ``{"rule_ids": [...]}`` from the code-scanning API.
    An empty list is a valid answer; a missing key is not.
    """
    data = _load_json(path, "code-scanning alert list")
    ids = data.get("rule_ids") if isinstance(data, dict) else None
    if not isinstance(ids, list):
        raise ReportError("alert list has no 'rule_ids' list; shape changed?")
    return {str(i) for i in ids}


def _published(directory: Path, cve: str) -> date | None:
    """Publication date of ``cve`` from ``<directory>/<cve>.json``, if known.

    The workflow saves one OSV record per reported CVE and saves nothing
    when OSV has none. ``None`` therefore means the age is unknown, and an
    unknown age is treated as old: it cannot be ruled out as recent.
    """
    path = directory / f"{cve}.json"
    if not path.is_file():
        return None
    data = _load_json(path, f"OSV record for {cve}")
    text = str(data.get("published") or "") if isinstance(data, dict) else ""
    try:
        return date.fromisoformat(text[:10])
    except ValueError as exc:
        raise ReportError(f"OSV record for {cve} has no usable 'published'") from exc


def classify_image_findings(
    reported: list[dict[str, str]],
    fixable_ids: set[str],
    vex_ids: set[str],
    open_findings: list[dict[str, str]],
    alert_ids: set[str],
    published_dir: Path,
    today: date,
    min_age_days: int,
) -> dict[str, list[dict[str, str]]]:
    """Sort what the image is reported for into what needs doing.

    ``reported`` is the unfiltered scan with the OpenVEX document applied.
    Returns ``decide`` (no fix, no statement, not accepted, old enough, seen
    by both scans), ``unapplied`` (reported although a statement names it),
    ``stale`` (accepted entries that no longer hold) and ``waiting``
    (undecided, but too recent or seen by one scan only). The first three
    gate the issue; ``waiting`` is informational.
    """
    open_ids = {f["id"] for f in open_findings}
    out: dict[str, list[dict[str, str]]] = {
        "decide": [],
        "unapplied": [],
        "stale": [],
        "waiting": [],
    }
    reported_ids: set[str] = set()
    for row in reported:
        cve = row["id"]
        if cve in reported_ids:
            continue
        reported_ids.add(cve)
        if cve in fixable_ids or cve in open_ids:
            continue
        if cve in vex_ids:
            out["unapplied"].append(row)
            continue
        published = _published(published_dir, cve)
        age = (today - published).days if published else None
        entry = {
            **row,
            "published": published.isoformat() if published else "unknown",
            "age": f"{age} days" if age is not None else "unknown",
        }
        if cve not in alert_ids:
            out["waiting"].append({**entry, "why": "seen by one scan only"})
        elif age is not None and age < min_age_days:
            out["waiting"].append(
                {**entry, "why": f"published {age} days ago, under {min_age_days}"}
            )
        else:
            out["decide"].append(entry)

    for finding in open_findings:
        cve = finding["id"]
        if cve in vex_ids:
            why = "the OpenVEX document also has a statement for it"
        elif cve in fixable_ids:
            why = "a fix is now available"
        elif cve not in reported_ids and cve not in alert_ids:
            why = "neither scan reports it any more"
        else:
            continue
        out["stale"].append({**finding, "why": why})
    return out


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
    image_open: tuple[Path, int, dict[str, list[dict[str, str]]]] | None = None,
) -> str:
    """Render the issue body.

    ``vex`` is ``(vex_path, package, gaps, considered, floor)`` when the
    OpenVEX completeness check ran, else ``None`` and the section is omitted.
    ``actions`` is ``(fixable, unfixable)`` from the zizmor report, else
    ``None`` and that section is omitted too. ``image_open`` is
    ``(open_findings_path, min_age_days, classified)`` when the unfiltered
    image scan was compared, else ``None`` and that section is omitted.
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
    undecided = _undecided_count(image_open[2]) if image_open else 0
    if undecided:
        item_noun = "finding" if undecided == 1 else "findings"
        headline += (
            f" **{undecided} image {item_noun} to decide** — no fix, and neither "
            "an OpenVEX statement nor an accepted entry matches."
        )
    parts = [
        MARKER,
        headline,
        "",
        (
            "This issue is maintained automatically: the body is rewritten on "
            "each run and the issue **closes itself** when the fixable list, the "
            "OpenVEX gap list and the image findings to decide are all empty. "
            "An open issue therefore means there is something to do right now."
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

    if image_open is not None:
        open_path, min_age, groups = image_open
        parts.append(f"## Image findings with no fix (`{open_path}`)")
        parts.append("")
        if not _undecided_count(groups):
            parts.append(
                "Nothing to decide. ✅ Every finding the published image is "
                "still reported for is fixable (above) or accepted in "
                f"`{open_path}`, and every accepted entry is still reported."
            )
            parts.append("")
        if groups["decide"]:
            parts.append(
                _table(
                    ["CVE", "Package", "Severity", "Published", "Age"],
                    [
                        [
                            f"`{r['id']}`",
                            r["package"],
                            r["severity"],
                            r["published"],
                            r["age"],
                        ]
                        for r in groups["decide"]
                    ],
                )
            )
            parts.append("")
            parts.append(
                f"These have had no fix for at least {min_age} days and nothing "
                "says why they are open. For each one, read where the fix or "
                "the flaw lands upstream, then either add a `not_affected` "
                "statement whose claim was checked against the image "
                "(docs/RELEASING.md, base-image statements item) or, when no "
                f"justification is true of it, add it to `{open_path}` with the "
                "reason and to the table in docs/verifying.md."
            )
            parts.append("")
        if groups["unapplied"]:
            parts.append(
                "Reported although the OpenVEX document has a statement, so the "
                "scanner did not apply it (check the product identifiers and "
                "the vulnerability name): "
                + ", ".join(f"`{r['id']}`" for r in groups["unapplied"])
                + "."
            )
            parts.append("")
        if groups["stale"]:
            parts.append(
                _table(
                    ["Accepted entry", "Package", "No longer holds because"],
                    [[f"`{r['id']}`", r["package"], r["why"]] for r in groups["stale"]],
                )
            )
            parts.append("")
            parts.append(
                f"Remove these from `{open_path}` and from the table in "
                "docs/verifying.md, or take the fix."
            )
            parts.append("")
        if groups["waiting"]:
            parts.append(
                "Not yet due — does not gate this issue: "
                + ", ".join(f"`{r['id']}` ({r['why']})" for r in groups["waiting"])
                + "."
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


def _undecided_count(groups: dict[str, list[dict[str, str]]]) -> int:
    """How many image findings gate the issue; ``waiting`` does not."""
    return len(groups["decide"]) + len(groups["unapplied"]) + len(groups["stale"])


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
    ap.add_argument(
        "--scout-all-sarif",
        type=Path,
        help="Scout SARIF of the same image without only-fixed, OpenVEX applied",
    )
    ap.add_argument(
        "--open-findings",
        type=Path,
        help="accepted findings that have no fix and no OpenVEX statement",
    )
    ap.add_argument(
        "--scout-alerts",
        type=Path,
        help='{"rule_ids": [...]} of the scheduled Scout scan\'s open alerts',
    )
    ap.add_argument(
        "--published-dir",
        type=Path,
        help="directory of OSV records, one <CVE>.json per reported CVE",
    )
    ap.add_argument(
        "--min-age-days",
        type=int,
        default=14,
        help="an undecided finding gates the issue once it is this old",
    )
    ap.add_argument(
        "--today",
        type=date.fromisoformat,
        default=None,
        help="date to measure ages from (default: today, UTC)",
    )
    args = ap.parse_args()
    if (args.vex is None) != (args.osv is None):
        ap.error("--vex and --osv must be given together")
    image_args = (
        args.scout_all_sarif,
        args.open_findings,
        args.scout_alerts,
        args.published_dir,
    )
    if any(a is not None for a in image_args) and (
        any(a is None for a in image_args)
        or args.vex is None
        or args.scout_sarif is None
    ):
        ap.error(
            "--scout-all-sarif, --open-findings, --scout-alerts and "
            "--published-dir must be given together, with --scout-sarif and --vex"
        )

    vex: tuple[Path, str, list[dict[str, str]], int, str] | None = None
    actions: tuple[list[dict[str, str]], list[dict[str, str]]] | None = None
    image_open: tuple[Path, int, dict[str, list[dict[str, str]]]] | None = None
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
        if args.scout_all_sarif is not None:
            today = args.today or datetime.now(UTC).date()
            groups = classify_image_findings(
                parse_scout_sarif(args.scout_all_sarif),
                {r["id"] for r in img_fixable},
                parse_vex_ids(args.vex),
                parse_open_findings(args.open_findings),
                parse_alert_ids(args.scout_alerts),
                args.published_dir,
                today,
                args.min_age_days,
            )
            image_open = (args.open_findings, args.min_age_days, groups)
    except ReportError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    body = build_body(
        py_fixable,
        py_unfixable,
        img_fixable,
        args.image,
        args.run_url,
        vex,
        actions,
        image_open,
    )
    args.out.write_text(body, encoding="utf-8")

    act_fixable = actions[0] if actions else []
    total = len(py_fixable) + len(img_fixable) + len(act_fixable)
    gap_count = len(vex[2]) if vex else 0
    undecided = _undecided_count(image_open[2]) if image_open else 0
    print(
        f"fixable: python={len(py_fixable)} image={len(img_fixable)} "
        f"actions={len(act_fixable)} "
        f"total={total}; unfixable (informational): {len(py_unfixable)}; "
        f"vex_gaps={gap_count}; image_undecided={undecided}"
    )

    title = f"Fixable vulnerabilities ({total})"
    if gap_count:
        title += f", OpenVEX gaps ({gap_count})"
    if undecided:
        title += f", image findings to decide ({undecided})"
    if step_output := os.environ.get("GITHUB_OUTPUT"):
        with open(step_output, "a", encoding="utf-8") as fh:
            fh.write(f"count={total}\n")
            fh.write(f"gaps={gap_count}\n")
            fh.write(f"title={title}\n")
            fh.write(f"undecided={undecided}\n")
            found = total or gap_count or undecided
            fh.write(f"has_findings={'true' if found else 'false'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
