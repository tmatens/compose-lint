#!/usr/bin/env python3
"""Execute the Forgejo guide's snippet against a live Forgejo (#573).

docs/forgejo.md promises a working Forgejo integration and closes with a
"Verified on Forgejo X, runner Y" line. A documented snippet without a
test is a promise we can't keep, so this script makes the claim
empirical, end to end:

1. Extract the snippet from docs/forgejo.md *verbatim* — the tested thing and
   the documented thing cannot drift, because they are one string.
2. Boot a throwaway Forgejo + act_runner stack
   (tests/forgejo_smoke/compose-forgejo-smoke.yml), bootstrap an admin
   user, an API token, and a runner registration over the Forgejo CLI.
3. Push a repo whose workflow *is* the snippet and whose
   docker-compose.yml is the shared clean fixture, dispatch it, and
   require the run to succeed. The clean fixture passes at the
   snippet's `--fail-on high`, so a green run proves install + lint
   actually happened on the Forgejo side.
4. Assert the guide's "Verified on ..." versions match the *live* instance
   and runner, so bumping the harness images without updating the claim
   fails loudly (and vice versa).

Run locally: python3 scripts/forgejo_smoke.py   (needs Docker + compose)
In CI: the forgejo-smoke workflow, weekly and on harness changes.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_FILE = REPO_ROOT / "tests" / "forgejo_smoke" / "compose-forgejo-smoke.yml"
SNIPPET_DOC = REPO_ROOT / "docs" / "forgejo.md"
CLEAN_FIXTURE = REPO_ROOT / "tests" / "smoke" / "clean.yml"

HOST_PORT = os.environ.get("FORGEJO_SMOKE_PORT", "3000")
API = f"http://localhost:{HOST_PORT}/api/v1"
USER = "smoke"
REPO = "snippet"
SNIPPET_MARKER = "# .forgejo/workflows/validate.yml"
VERIFIED_RE = re.compile(r"Verified on Forgejo ([0-9.]+), runner ([0-9.]+)")

WAIT_API_SECONDS = 120
WAIT_RUN_SECONDS = 420


def log(msg: str) -> None:
    print(msg, flush=True)


def fail(msg: str) -> None:
    print(f"::error::{msg}", flush=True)
    raise SystemExit(1)


def sh(
    *args: str, echo: bool = True, capture: bool = False
) -> subprocess.CompletedProcess[str]:
    """Run a command; `echo=False` for argv carrying credentials."""
    if echo:
        log("+ " + " ".join(args))
    return subprocess.run(list(args), check=True, capture_output=capture, text=True)


def compose(*args: str, echo: bool = True, capture: bool = False):
    return sh(
        "docker", "compose", "-f", str(COMPOSE_FILE), *args, echo=echo, capture=capture
    )


def forgejo_cli(*args: str, echo: bool = True) -> str:
    """Run the Forgejo CLI inside the server container (as the git user)."""
    out = compose(
        "exec", "-T", "-u", "1000", "forgejo", "forgejo", *args, echo=echo, capture=True
    )
    return out.stdout.strip()


def api(
    method: str,
    path: str,
    token: str | None = None,
    body: dict[str, Any] | None = None,
) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, method=method, data=data)
    if token:
        req.add_header("Authorization", "token " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except OSError as e:
        # URLError, plus raw socket errors (connection refused/reset while
        # the instance is still booting) — callers treat 0 as "not up yet".
        return 0, str(e)


def extract_snippet() -> str:
    text = SNIPPET_DOC.read_text(encoding="utf-8")
    blocks = re.findall(
        rf"```yaml\n({re.escape(SNIPPET_MARKER)}\n.*?)```", text, re.DOTALL
    )
    if len(blocks) != 1:
        fail(
            f"expected exactly one docs/forgejo.md code fence starting with "
            f"'{SNIPPET_MARKER}', found {len(blocks)}"
        )
    return blocks[0]


def doc_verified_versions() -> tuple[str, str]:
    matches = VERIFIED_RE.findall(SNIPPET_DOC.read_text(encoding="utf-8"))
    if len(matches) != 1:
        fail(
            "expected exactly one 'Verified on Forgejo X, runner Y' line "
            "in docs/forgejo.md"
        )
    return matches[0]


def wait_for_api() -> str:
    deadline = time.monotonic() + WAIT_API_SECONDS
    while time.monotonic() < deadline:
        status, body = api("GET", "/version")
        if status == 200:
            return str(body["version"])
        time.sleep(2)
    fail(f"Forgejo API did not come up within {WAIT_API_SECONDS}s")
    raise AssertionError  # unreachable


def main() -> None:
    snippet = extract_snippet()
    log(f"docs/forgejo.md snippet extracted ({len(snippet.splitlines())} lines).")
    claimed_forgejo, claimed_runner = doc_verified_versions()

    password = secrets.token_urlsafe(18)
    exit_code = 0
    try:
        compose("up", "-d", "--quiet-pull", "forgejo")
        live_version = wait_for_api()
        log(f"Forgejo up: {live_version}")

        forgejo_cli(
            "admin",
            "user",
            "create",
            "--admin",
            "--username",
            USER,
            "--password",
            password,
            "--email",
            "smoke@example.invalid",
            echo=False,
        )
        token = forgejo_cli(
            "admin",
            "user",
            "generate-access-token",
            "--username",
            USER,
            "--token-name",
            "smoke",
            "--scopes",
            "all",
            "--raw",
            echo=False,
        ).splitlines()[-1]
        runner_token = forgejo_cli("actions", "generate-runner-token", echo=False)
        # Mask both in Actions logs; they are sandbox-scoped but tidy is tidy.
        for value in (token, runner_token):
            log(f"::add-mask::{value}")

        os.environ["RUNNER_TOKEN"] = runner_token
        compose("up", "-d", "runner")

        status, body = api(
            "POST",
            "/user/repos",
            token,
            {"name": REPO, "default_branch": "main", "auto_init": False},
        )
        if status != 201:
            fail(f"repo creation failed ({status}): {body}")

        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            wf = work / ".forgejo" / "workflows" / "validate.yml"
            wf.parent.mkdir(parents=True)
            wf.write_text(snippet, encoding="utf-8")
            (work / "docker-compose.yml").write_text(
                CLEAN_FIXTURE.read_text(encoding="utf-8"), encoding="utf-8"
            )
            g = (
                "git",
                "-C",
                str(work),
                "-c",
                "user.name=smoke",
                "-c",
                "user.email=smoke@example.invalid",
            )
            sh(*g, "init", "-q", "-b", "main")
            sh(*g, "add", "-A")
            sh(*g, "commit", "-q", "--no-gpg-sign", "-m", "snippet under test")
            push_url = f"http://{USER}:{token}@localhost:{HOST_PORT}/{USER}/{REPO}.git"
            sh(*g, "push", "-q", push_url, "main", echo=False)
        log("Snippet repo pushed.")

        status, body = api(
            "POST",
            f"/repos/{USER}/{REPO}/actions/workflows/validate.yml/dispatches",
            token,
            {"ref": "main"},
        )
        if status not in (200, 204):
            fail(f"workflow dispatch failed ({status}): {body}")
        log("Workflow dispatched; waiting for the run...")

        deadline = time.monotonic() + WAIT_RUN_SECONDS
        outcome = None
        while time.monotonic() < deadline:
            status, body = api("GET", f"/repos/{USER}/{REPO}/actions/tasks", token)
            if status == 200 and body.get("workflow_runs"):
                states = {r["status"] for r in body["workflow_runs"]}
                if states & {"failure", "cancelled"}:
                    outcome = "failure"
                    break
                if states == {"success"}:
                    outcome = "success"
                    break
            time.sleep(5)
        if outcome != "success":
            compose("logs", "--tail", "150", "runner")
            fail(
                "the documented snippet did not complete successfully on the live "
                f"Forgejo (outcome: {outcome or 'timeout'})"
            )
        log("Snippet workflow succeeded on the live Forgejo.")

        # The claim must match what actually ran.
        live_forgejo = live_version.split("+")[0]
        runner_version_out = compose(
            "exec", "-T", "runner", "forgejo-runner", "--version", capture=True
        ).stdout.strip()
        m = re.search(r"v?([0-9][0-9.]*)", runner_version_out)
        live_runner = m.group(1) if m else runner_version_out
        if (claimed_forgejo, claimed_runner) != (live_forgejo, live_runner):
            fail(
                "docs/forgejo.md's verified-on line is stale: claims Forgejo "
                f"{claimed_forgejo} / runner {claimed_runner}, but this run "
                f"used Forgejo {live_forgejo} / runner {live_runner}. Update "
                "the docs/forgejo.md line (and the harness images if intended)."
            )
        log(
            f"Verified on Forgejo {live_forgejo}, runner {live_runner} — "
            "Guide claim matches the live run."
        )
    except subprocess.CalledProcessError as e:
        print(f"::error::command failed with exit {e.returncode}", flush=True)
        exit_code = 1
    finally:
        compose("down", "-v", "--remove-orphans")
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
