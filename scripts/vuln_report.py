#!/usr/bin/env python3
"""Build the rolling "fixable vulnerabilities" issue body.

Consumes a pip-audit JSON report and (optionally) a Docker Scout SARIF
report, and emits a Markdown body plus a has-findings flag.

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
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

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
) -> str:
    total = len(py_fixable) + len(img_fixable)
    noun = "vulnerability" if total == 1 else "vulnerabilities"
    tail = (
        " — every advisory below has a fix available, at any severity."
        if total
        else " — nothing to fix right now."
    )
    parts = [
        MARKER,
        f"**{total} fixable {noun}**{tail}",
        "",
        (
            "This issue is maintained automatically: the body is rewritten on "
            "each run and the issue **closes itself** when the fixable list is "
            "empty. An open issue therefore means there is something to fix "
            "right now."
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
    args = ap.parse_args()

    try:
        py_fixable, py_unfixable = parse_pip_audit(args.pip_audit)
        img_fixable = parse_scout_sarif(args.scout_sarif) if args.scout_sarif else []
    except ReportError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    body = build_body(py_fixable, py_unfixable, img_fixable, args.image, args.run_url)
    args.out.write_text(body, encoding="utf-8")

    total = len(py_fixable) + len(img_fixable)
    print(
        f"fixable: python={len(py_fixable)} image={len(img_fixable)} "
        f"total={total}; unfixable (informational): {len(py_unfixable)}"
    )

    if step_output := os.environ.get("GITHUB_OUTPUT"):
        with open(step_output, "a", encoding="utf-8") as fh:
            fh.write(f"count={total}\n")
            fh.write(f"has_findings={'true' if total else 'false'}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
