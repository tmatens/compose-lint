#!/usr/bin/env python3
"""Report upstream end-of-life dates the project's platform floors are riding toward.

The Python 3.10 drop (#643) showed the failure mode this exists to prevent:
a platform EOL everyone can see coming still arrives "suddenly" unless
something is watching the calendar, and post-1.0 the cost of being surprised
is a forced MAJOR (or carrying an EOL interpreter inside the stability
contract). Vulnerabilities have vuln-report.yml; release schedules had
nothing.

What it watches, against https://endoflife.date:

- **python**, the `requires-python` floor — parsed live from pyproject.toml,
  so the watch moves automatically when the floor does.
- **python**, new stable minors missing from ci.yml's test matrix — the
  ROADMAP commits to adding one within ~3 months of each October release.
- **debian**, the Docker runtime base (distroless on Debian, ADR-009).
- **github-actions-runner-images**, the exact runner labels CI stands on
  (ubuntu-24.04, and os-smoke's macos-26/windows-2025) — the image
  calendar, not the OS calendar, because GitHub retires images first.
- **docker-engine**, the major the rule premises are grounded on: its EOL
  is the signal to re-ground validate_rule_premises.py on the current
  engine.

PyYAML and the dev dependencies are deliberately absent: they publish no
support lifecycle (not on endoflife.date), so their risks are watched by
the tools that fit them — vuln-report.yml for vulnerabilities, Renovate
for staleness, the CI matrix for new-interpreter compatibility.

Cycles other than the Python floor are declared here rather than parsed,
because they live in comments, ADR prose, and `runs-on:` lines; each
declaration carries a grep-able anchor and the script FAILS (exit 2) if the
anchor no longer appears where it claims to — a stale watch is worse than no
watch, because it reads as "covered" (the capability-drop-harness lesson:
a check run against the wrong posture returns a confidently wrong answer).

Exit codes: 0 = ran, nothing due. 1 = ran, at least one item due (report on
stdout, ready for an issue body). 2 = the script itself could not produce a
trustworthy answer (network, parse, stale anchor). eol-watch.yml turns 1 into
a rolling issue and treats 2 as a workflow failure.

Offline by design in tests: every function below the __main__ guard is pure
(today and API payloads are parameters); only fetch()/main() touch the
network and the filesystem.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import pathlib
import re
import sys
import tomllib
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent
API = "https://endoflife.date/api/{product}.json"

# How far ahead of an EOL date an item becomes "due". Six months: long
# enough to announce a deprecation, ship the warning release, honour the
# one-MINOR grace period of docs/compatibility.md, and land the drop —
# the whole #650/#643 sequence — without the calendar forcing the pace.
WINDOW_DAYS = 180

# ~3 months, the ROADMAP's window for adding a new CPython minor to the
# CI matrix after its October release.
MATRIX_ADD_DAYS = 92


@dataclasses.dataclass(frozen=True)
class Watch:
    """One (product, cycle) pair the project depends on."""

    product: str  # endoflife.date product slug
    cycle: str  # e.g. "3.11", "13", "24.04"
    role: str  # why the project cares, verbatim in the report
    # Prove the declaration still matches the repo: `pattern` must appear in
    # `anchor_file`. None for cycles parsed live (already self-proving).
    anchor_file: str | None = None
    anchor_pattern: str | None = None


@dataclasses.dataclass(frozen=True)
class Finding:
    """One due item, renderable as a report bullet."""

    headline: str
    detail: str


def python_floor(pyproject_text: str) -> str:
    """The requires-python floor as a cycle string, e.g. ``3.11``."""
    data = tomllib.loads(pyproject_text)
    spec = data["project"]["requires-python"]
    m = re.fullmatch(r">=\s*(\d+\.\d+)", spec)
    if m is None:
        raise ValueError(
            f"requires-python is {spec!r}, not the '>=X.Y' form this watch "
            "knows how to read — update eol_watch.py alongside the new form"
        )
    return m.group(1)


def ci_matrix(ci_text: str) -> list[str]:
    """The python-version matrix of ci.yml's test job."""
    m = re.search(r'python-version:\s*\[([0-9.", ]+)\]', ci_text)
    if m is None:
        raise ValueError("no python-version matrix found in ci.yml")
    return re.findall(r"\d+\.\d+", m.group(1))


def check_anchor(watch: Watch, text: str) -> None:
    """Fail loudly when a declared cycle no longer matches the repo."""
    assert watch.anchor_pattern is not None
    if not re.search(watch.anchor_pattern, text):
        raise ValueError(
            f"{watch.product} {watch.cycle}: anchor {watch.anchor_pattern!r} "
            f"not found in {watch.anchor_file} — the declaration in "
            "eol_watch.py is stale; update the Watch to match the repo"
        )


def _cycle_row(payload: list[dict], cycle: str) -> dict:
    for row in payload:
        if str(row.get("cycle")) == cycle:
            return row
    raise ValueError(f"cycle {cycle} not in endoflife.date payload")


def _eol_date(row: dict) -> dt.date | None:
    """The row's EOL as a date; None when not date-bounded (false/None)."""
    eol = row.get("eol")
    if isinstance(eol, str):
        return dt.date.fromisoformat(eol)
    return None  # false = "no EOL scheduled"; treat as not due


def check_eol(watch: Watch, payload: list[dict], today: dt.date) -> Finding | None:
    """A finding when the watched cycle's EOL is inside the window (or past)."""
    eol = _eol_date(_cycle_row(payload, watch.cycle))
    if eol is None:
        return None
    days = (eol - today).days
    if days > WINDOW_DAYS:
        return None
    if days < 0:
        when = f"reached upstream EOL {-days} days ago"
    else:
        when = f"reaches upstream EOL in {days} days"
    return Finding(
        headline=f"{watch.product} {watch.cycle} {when} ({eol.isoformat()})",
        detail=(
            f"Used as: {watch.role}. Per docs/compatibility.md, announce the "
            "deprecation, warn at runtime, honour one MINOR of grace, then "
            "move the floor — start now so the calendar does not set the pace."
        ),
    )


def check_new_python(
    payload: list[dict], matrix: list[str], today: dt.date
) -> list[Finding]:
    """Findings for released stable CPython minors absent from the CI matrix."""
    findings = []
    ceiling = max(tuple(int(p) for p in v.split(".")) for v in matrix)
    for row in payload:
        cycle = str(row.get("cycle"))
        release = row.get("releaseDate")
        if cycle in matrix or not isinstance(release, str):
            continue
        try:
            if tuple(int(p) for p in cycle.split(".")) <= ceiling:
                continue  # older than the matrix ceiling: dropped, not pending
        except ValueError:
            continue  # non-numeric cycle (endoflife.date has none for python)
        released = dt.date.fromisoformat(release)
        age = (today - released).days
        if age < 0:
            continue  # not released yet
        overdue = "OVERDUE — " if age > MATRIX_ADD_DAYS else ""
        findings.append(
            Finding(
                headline=(
                    f"{overdue}Python {cycle} released {age} days ago "
                    f"({release}) and is not in the CI matrix"
                ),
                detail=(
                    "docs/ROADMAP.md commits to adding each new minor within "
                    f"~3 months of release; adding one is a PATCH. Matrix: {matrix}."
                ),
            )
        )
    return findings


def render(findings: list[Finding]) -> str:
    lines = [
        "Platform end-of-life radar — produced by scripts/eol_watch.py",
        f"(window: {WINDOW_DAYS} days; data: endoflife.date)",
        "",
    ]
    for f in findings:
        lines += [f"- **{f.headline}**", f"  {f.detail}"]
    return "\n".join(lines) + "\n"


def fetch(product: str) -> list[dict]:
    with urllib.request.urlopen(API.format(product=product), timeout=30) as resp:
        return json.load(resp)


def build_watches(floor: str) -> list[Watch]:
    """Every (product, cycle) the project rides on.

    Runner labels are watched as `github-actions-runner-images` cycles, not
    OS cycles: GitHub retires an image on its own schedule (the ubuntu-20.04
    runner went 2025-04-15, before the OS did), so the OS calendar is the
    wrong clock for a `runs-on:` line.
    """
    return [
        Watch("python", floor, "requires-python floor (pyproject.toml)"),
        Watch(
            "debian",
            "13",
            "Docker runtime base image, distroless on Debian (ADR-009)",
            anchor_file="Dockerfile",
            anchor_pattern=r"Debian 13|trixie",
        ),
        Watch(
            "github-actions-runner-images",
            "ubuntu-24.04",
            "CI runner image (ci.yml and siblings)",
            anchor_file=".github/workflows/ci.yml",
            anchor_pattern=r"ubuntu-24\.04",
        ),
        Watch(
            "github-actions-runner-images",
            "macos-26",
            "os-smoke runner image (macOS leg)",
            anchor_file=".github/workflows/os-smoke.yml",
            anchor_pattern=r"macos-26",
        ),
        Watch(
            "github-actions-runner-images",
            "windows-2025",
            "os-smoke runner image (Windows leg)",
            anchor_file=".github/workflows/os-smoke.yml",
            anchor_pattern=r"windows-2025",
        ),
        Watch(
            "docker-engine",
            "29",
            "Docker Engine major the rule premises are grounded on (ADR-028); "
            "when it EOLs, re-ground scripts/validate_rule_premises.py on the "
            "current engine and update the recorded posture",
            anchor_file="docs/adr/028-pre-1.0-rule-id-sweep.md",
            anchor_pattern=r"Docker Engine 29",
        ),
    ]


def main() -> int:
    floor = python_floor((REPO / "pyproject.toml").read_text())
    matrix = ci_matrix((REPO / ".github/workflows/ci.yml").read_text())
    watches = build_watches(floor)
    today = dt.date.today()
    findings: list[Finding] = []
    payloads: dict[str, list[dict]] = {}
    for w in watches:
        if w.anchor_file is not None:
            check_anchor(w, (REPO / w.anchor_file).read_text())
        payloads.setdefault(w.product, fetch(w.product))
        if (f := check_eol(w, payloads[w.product], today)) is not None:
            findings.append(f)
    findings += check_new_python(payloads["python"], matrix, today)
    if not findings:
        print("Nothing due within the window.")
        return 0
    print(render(findings))
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 — exit 2 must cover every failure
        print(f"eol_watch: cannot produce a trustworthy answer: {exc}", file=sys.stderr)
        sys.exit(2)
