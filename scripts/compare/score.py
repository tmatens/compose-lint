#!/usr/bin/env python3
"""Turn a run.sh output directory into the tables on docs/compare.md.

    python scripts/compare/score.py OUT_DIR

A cell is scored from what the tool printed. A finding counts for a row only
when it comes from the tool's own rule for that setting (RULES below) and is
reported on the service the row is about. A tool with no rule for a setting
gets a dash, so a miss is only ever charged to a tool that claims the check.

The tables are printed once for the fixtures as written and once with the
obsolete `version:` key added, because two tools behave differently with it.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

TOOLS = ["compose-lint", "kics", "docksec", "semgrep", "dclint"]
TITLE = {
    "compose-lint": "compose-lint",
    "kics": "KICS",
    "docksec": "DockSec",
    "semgrep": "Semgrep",
    "dclint": "DCLint",
}

# setting -> tool -> rule names that count as that tool's rule for it. A tool
# missing from a setting has no rule for it.
RULES: dict[str, dict[str, set[str]]] = {
    "socket": {
        "compose-lint": {"CL-0001"},
        "kics": {"Docker Socket Mounted In Container"},
        "docksec": {"compose-docker-socket-mount"},
        "semgrep": {"exposing-docker-socket-volume"},
    },
    "privileged": {
        "compose-lint": {"CL-0002"},
        "kics": {"Privileged Containers Enabled"},
        "docksec": {"compose-privileged"},
        "semgrep": {"privileged-service"},
    },
    "nnp": {
        "compose-lint": {"CL-0003"},
        "kics": {"No New Privileges Not Set", "Security Opt Not Set"},
        "docksec": {"compose-no-new-privileges"},
        "semgrep": {"no-new-privileges"},
    },
    "latest": {
        "compose-lint": {"CL-0004"},
        "docksec": {"compose-latest-or-untagged-image"},
        "dclint": {"service-image-require-explicit-tag"},
    },
    "port": {
        "compose-lint": {"CL-0005"},
        "kics": {"Container Traffic Not Bound To Host Interface"},
        "docksec": {"compose-port-bound-all-interfaces"},
        "dclint": {"no-unbound-port-interfaces"},
    },
    "caps": {
        "compose-lint": {"CL-0006"},
        "kics": {"Container Capabilities Unrestricted"},
    },
    "cap-add": {
        "compose-lint": {"CL-0024"},
        "kics": {"Container Capabilities Unrestricted"},
        "docksec": {"compose-dangerous-capabilities"},
    },
    "rootfs": {
        "compose-lint": {"CL-0007"},
        "docksec": {"compose-writable-root-fs"},
        "semgrep": {"writable-filesystem-service"},
    },
    "hostnet": {
        "compose-lint": {"CL-0008"},
        "kics": {"Shared Host Network Namespace"},
        "docksec": {"compose-host-network"},
    },
    "seccomp": {
        "compose-lint": {"CL-0009"},
        "kics": {"Default Seccomp Profile Disabled"},
        "docksec": {"compose-disabled-security-opt"},
        "semgrep": {"seccomp-confinement-disabled"},
    },
    "apparmor": {
        "compose-lint": {"CL-0009"},
        "docksec": {"compose-disabled-security-opt"},
    },
    "selinux": {
        "compose-lint": {"CL-0009"},
        "docksec": {"compose-disabled-security-opt"},
        "semgrep": {"selinux-separation-disabled"},
    },
    "host-namespace": {
        "compose-lint": {"CL-0010"},
        "kics": {"Host Namespace is Shared", "Shared Host IPC Namespace"},
        "docksec": {"compose-host-namespace"},
    },
    "host-path": {
        "compose-lint": {"CL-0013", "CL-0025"},
        "kics": {"Volume Has Sensitive Host Directory"},
        "docksec": {"compose-sensitive-host-mount"},
    },
    "logging": {"compose-lint": {"CL-0014"}},
    "user-root": {
        "compose-lint": {"CL-0018"},
        "docksec": {"compose-no-non-root-user"},
    },
    "no-user": {"docksec": {"compose-no-non-root-user"}},
    "digest": {"compose-lint": {"CL-0019"}},
    "credential": {
        "compose-lint": {"CL-0020"},
        "kics": {"Passwords And Secrets - Generic Password"},
        "docksec": {"compose-plaintext-secret-env"},
    },
    "limits": {
        "compose-lint": {"CL-0026"},
        "kics": {"Memory Not Limited", "Cpus Not Limited"},
        "docksec": {"compose-no-resource-limits"},
    },
    "pids": {"kics": {"Pids Limit Not Set"}},
    "default-network": {"docksec": {"compose-no-network-segmentation"}},
    "restart": {},
    "rw-volume": {},
}

SAME_FILE = [
    ("Docker socket mounted", "socket", "socket"),
    ("`privileged: true`", "privileged", "privileged"),
    ("`no-new-privileges` missing", "nnp", "nnp"),
    ("Unpinned `:latest` tag", "latest", "latest"),
    ("Port published on `0.0.0.0`", "ports", "port"),
    ("No `cap_drop: [ALL]`", "caps", "caps"),
    ("Writable root filesystem", "rootfs", "rootfs"),
    ("`network_mode: host`", "hostnet", "hostnet"),
    ("`seccomp:unconfined`", "seccomp", "seccomp"),
    ("`pid: host` / `ipc: host`", "pidhost", "host-namespace"),
    ("Sensitive host path mounted", "hostpath", "host-path"),
    ("`logging: driver: none`", "nolog", "logging"),
    ("`user: root`", "root", "user-root"),
    ("Tag without digest", "nodigest", "digest"),
    ("Credential in `environment:`", "secret", "credential"),
    ("No memory/CPU limits", "nolimits", "limits"),
]

OWASP = [
    ("1 — Docker socket mounted", "rule1-socket", "socket"),
    ("2 — `user: root` set explicitly", "rule2-explicit-root", "user-root"),
    ("2 — no `user:`, image default", "rule2-no-user", "no-user"),
    ("3 — `privileged: true`", "rule3-privileged", "privileged"),
    ("3 — default capability set, nothing dropped", "rule3-all-caps", "caps"),
    (
        "3 — `cap_drop: [ALL]` then `cap_add: [SYS_ADMIN]`",
        "rule3-sys-admin",
        "cap-add",
    ),
    ("4 — `no-new-privileges` not set", "rule4-nnp-missing", "nnp"),
    ("5 — `network_mode: host`", "rule5-host-network", "hostnet"),
    (
        "5 — no `networks:`, joins the shared default network",
        "rule5-default-network",
        "default-network",
    ),
    ("5a — port published on `0.0.0.0`", "rule5a-all-interfaces", "port"),
    ("6 — `seccomp:unconfined`", "rule6-seccomp-off", "seccomp"),
    ("6 — `apparmor:unconfined`", "rule6-apparmor-off", "apparmor"),
    ("6 — SELinux `label:disable`", "rule6-selinux-off", "selinux"),
    ("7 — no memory or CPU limits", "rule7-no-limits", "limits"),
    ("7 — no `pids_limit`", "rule7-no-pids-limit", "pids"),
    ("7 — `restart: always`, unbounded", "rule7-restart-always", "restart"),
    ("8 — root filesystem writable", "rule8-writable-root", "rootfs"),
    ("8 — host directory mounted read-write", "rule8-rw-volume", "rw-volume"),
    (
        "12 — credential as a literal `environment:` value",
        "rule12-plaintext",
        "credential",
    ),
    ("13 — mutable `:latest` tag", "rule13-latest", "latest"),
    ("13 — version tag without a digest", "rule13-no-digest", "digest"),
]

MULTI = [
    ("Written inline (control)", "inline"),
    ("`extends:` a service in the same file", "extends-same-file"),
    ("`extends:` a service in another file", "extends-other-file"),
    ("`include:` of another file", "include"),
    ("`compose.override.yml`", "override"),
    ("YAML anchor and `<<:` merge key", "anchor"),
    ("`${VAR:-default}`", "interpolation-default"),
    ("A value from `.env`", "dotenv"),
]

EXTRA = [
    ("Socket in the long `volumes:` syntax", "long-syntax", "socket"),
    ("Port in the long `ports:` syntax", "long-syntax", "port"),
    (
        "Socket as `secrets:` with `file: /var/run/docker.sock`",
        "secret-file",
        "socket",
    ),
    ("`seccomp=unconfined`", "seccomp-equals", "seccomp"),
    ("`seccomp:unconfined` (control)", "seccomp-colon", "seccomp"),
    ("Socket mounted at another path", "socket-elsewhere", "socket"),
    (
        "`seccomp:unconfined` beside `apparmor:unconfined`",
        "seccomp-with-apparmor",
        "seccomp",
    ),
]

SAFE = [
    (
        "`privileged: true`, set back to `false` by `compose.override.yml`",
        "safe-override",
        ["privileged"],
    ),
    ("Port bound to `${BIND:-127.0.0.1}`", "safe-default", ["port"]),
    ("`no-new-privileges=true`, the `=` spelling", "safe-nnp-equals", ["nnp"]),
    (
        "Port, socket and `privileged` from a `.env` with safe values",
        "safe-dotenv",
        ["port", "socket", "privileged"],
    ),
]

# The multi-file tables leave DCLint out and do not charge DockSec for the
# port, whose rule covers a fixed list of ports that excludes 8080.
MULTI_TOOLS = ["compose-lint", "kics", "docksec", "semgrep"]
MULTI_NO_RULE = {("docksec", "port")}

# In the anchor scenario the settings are written under this top-level key
# and merged into the service, so a finding reported there is on the service.
ANCHOR_KEY = "x-danger"


def _load(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _service_at(src: Path | None, name: str, line: int) -> str:
    """The service (or top-level key) that holds a line of a fixture file."""
    if src is None:
        return "?"
    path = src / name
    if not path.is_file():
        return "?"
    top = owner = "?"
    for number, text in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = re.match(r"^(\S[^:]*):", text)
        if match:
            top = match.group(1)
            owner = top if top != "services" else "?"
        elif top == "services":
            match = re.match(r"^  ([A-Za-z0-9_.-]+):", text)
            if match:
                owner = match.group(1)
        if number >= line:
            break
    return owner


def findings(
    tool: str, run: Path, src: Path | None, shift: int = 0
) -> set[tuple[str, str]]:
    """Every (service, rule) the tool reported in one run directory.

    ``shift`` is the number of lines run.sh put above each fixture file (one,
    for the `version:` variant), so a reported line maps back to the fixture.
    """
    found: set[tuple[str, str]] = set()
    if tool == "compose-lint":
        data = _load(run / "compose-lint.stdout")
        if isinstance(data, dict):
            for item in data.get("findings", []):
                if not item.get("suppressed"):
                    found.add((item.get("service") or "?", item["rule_id"]))
    elif tool == "kics":
        for report in sorted((run / "kics").glob("*.json")):
            data = _load(report)
            if not isinstance(data, dict):
                continue
            for query in data.get("queries", []):
                for hit in query.get("files", []):
                    key = hit.get("search_key", "")
                    match = re.match(r"services\.([^.]+)", key)
                    if match:
                        service = match.group(1)
                    elif key:
                        service = key.split(".")[0]
                    else:
                        # The secrets scanner reports a line and no key.
                        name = hit.get("file_name", "").split("src/", 1)[-1]
                        service = _service_at(
                            src, name, int(hit.get("line", 0)) - shift
                        )
                    found.add((service or "?", query["query_name"]))
    elif tool == "docksec":
        for report in sorted((run / "docksec").glob("*.json")):
            data = _load(report)
            if not isinstance(data, dict):
                continue
            for item in data.get("vulnerabilities", []):
                parts = str(item.get("Target", "")).split(":")
                service = parts[1] if len(parts) > 1 else "?"
                found.add((service, item["VulnerabilityID"]))
    elif tool == "semgrep":
        data = _load(run / "semgrep.stdout")
        if isinstance(data, dict):
            for item in data.get("results", []):
                name = Path(item["path"]).relative_to("/src").as_posix()
                service = _service_at(src, name, item["start"]["line"] - shift)
                found.add((service, item["check_id"].split(".")[-1]))
    elif tool == "dclint":
        data = _load(run / "dclint.stdout")
        if isinstance(data, list):
            for entry in data:
                name = Path(entry["filePath"]).relative_to("/src").as_posix()
                for message in entry.get("messages", []):
                    match = re.search(r'Service "([^"]+)"', message["message"])
                    service = (
                        match.group(1)
                        if match
                        else _service_at(src, name, message.get("line", 0) - shift)
                    )
                    found.add((service, message["rule"]))
    return found


# Rules a tool reports once for the whole file and not on a service.
FILE_WIDE = {("docksec", "default-network"): "global"}


def hit(found: set[tuple[str, str]], tool: str, setting: str, service: str) -> bool:
    rules = RULES[setting].get(tool, set())
    where = {service, FILE_WIDE.get((tool, setting), service)}
    return any(s in where and r in rules for s, r in found)


def single(out: Path, fixtures: Path, name: str, rows: list, variant: str) -> None:
    run = out / name / variant
    src = fixtures / name
    shift = 1 if variant == "version-key" else 0
    found = {tool: findings(tool, run, src, shift) for tool in TOOLS}
    print(f"\n### {name}, {variant}\n")
    print("| Row | " + " | ".join(TITLE[t] for t in TOOLS) + " |")
    print("|---|" + "---|" * len(TOOLS))
    caught = dict.fromkeys(TOOLS, 0)
    no_rule = dict.fromkeys(TOOLS, 0)
    missed = dict.fromkeys(TOOLS, 0)
    for label, service, setting in rows:
        cells = []
        for tool in TOOLS:
            if tool not in RULES[setting]:
                cells.append("—")
                no_rule[tool] += 1
            elif hit(found[tool], tool, setting, service):
                cells.append("✅")
                caught[tool] += 1
            else:
                cells.append("✗")
                missed[tool] += 1
        print(f"| {label} | " + " | ".join(cells) + " |")
    for title, counts in (
        (f"Flagged, of {len(rows)}", caught),
        ("No rule for it", no_rule),
        ("Has a rule, missed it", missed),
    ):
        print(f"| **{title}** | " + " | ".join(str(counts[t]) for t in TOOLS) + " |")
    totals = ", ".join(f"{TITLE[t]} {len(found[t])}" for t in TOOLS)
    print(f"\nDistinct (service, rule) pairs reported: {totals}")
    for tool in ("checkov", "trivy", "hadolint"):
        text = (run / f"{tool}.stdout").read_text(encoding="utf-8", errors="replace")
        code = (run / f"{tool}.exit").read_text().strip()
        print(f"{tool}: exit {code}, {len(text)} bytes of output")


def multi_cell(found, tool: str, setting: str) -> str:
    if tool not in RULES[setting] or (tool, setting) in MULTI_NO_RULE:
        return "—"
    if hit(found, tool, setting, "app") or hit(found, tool, setting, ANCHOR_KEY):
        return "✅"
    if hit(found, tool, setting, "base"):
        return "◐"
    return "✗"


def multi(out: Path, fixtures: Path, variant: str) -> None:
    def load(scenario: str):
        run = out / "multi" / scenario / variant
        src = fixtures / "multi" / scenario
        shift = 1 if variant == "version-key" else 0
        return {tool: findings(tool, run, src, shift) for tool in TOOLS}

    print(f"\n### multi, {variant}\n")
    for setting, title in (
        ("privileged", "`privileged: true`"),
        ("socket", "The Docker socket mount"),
        ("port", "A port published on all interfaces"),
    ):
        print(f"\n**{title}**\n")
        print(
            "| Where the setting comes from | "
            + " | ".join(TITLE[t] for t in MULTI_TOOLS)
            + " | DCLint |"
        )
        print("|---|" + "---|" * (len(MULTI_TOOLS) + 1))
        for label, scenario in MULTI:
            found = load(scenario)
            cells = [multi_cell(found[t], t, setting) for t in MULTI_TOOLS]
            cells.append(multi_cell(found["dclint"], "dclint", setting))
            print(f"| {label} | " + " | ".join(cells) + " |")
    print("\n**More scenarios**\n")
    print("| Scenario | " + " | ".join(TITLE[t] for t in MULTI_TOOLS) + " |")
    print("|---|" + "---|" * len(MULTI_TOOLS))
    for label, scenario, setting in EXTRA:
        found = load(scenario)
        cells = [multi_cell(found[t], t, setting) for t in MULTI_TOOLS]
        print(f"| {label} | " + " | ".join(cells) + " |")
    print("\n**Looks dangerous, deploys safely**\n")
    print("| Scenario | " + " | ".join(TITLE[t] for t in TOOLS) + " |")
    print("|---|" + "---|" * len(TOOLS))
    for label, scenario, settings in SAFE:
        found = load(scenario)
        cells = []
        for tool in TOOLS:
            mine = [
                s
                for s in settings
                if tool in RULES[s] and (tool, s) not in MULTI_NO_RULE
            ]
            if not mine:
                cells.append("No rule")
            elif any(
                hit(found[tool], tool, s, service)
                for s in mine
                for service in ("app", "base", ANCHOR_KEY)
            ):
                cells.append("False alarm")
            else:
                cells.append("Quiet")
        print(f"| {label} | " + " | ".join(cells) + " |")


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    out = Path(sys.argv[1])
    fixtures = Path(__file__).resolve().parent / "fixtures"
    print((out / "versions.txt").read_text(encoding="utf-8"))
    for variant in ("as-written", "version-key"):
        single(out, fixtures, "same-file", SAME_FILE, variant)
        single(out, fixtures, "owasp", OWASP, variant)
        multi(out, fixtures, variant)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
