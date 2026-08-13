"""The release layer must not be the weak path.

Publishing is where this repo's credentials and its provenance chain live, so a
check that exists on the normal path and not on the emergency one is worse than
having neither: the escape hatch is the path taken under pressure.

These assert on the workflow files themselves. They cannot run a release, so
they check the properties a release depends on — that every credential-bearing
job transitively reaches the tag gate, that the gate is defined once, and that
no workflow resolves dependencies from an index it does not pin.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

# Anything that reaches a publishing credential, a signing key, or the registry.
_CREDENTIAL_MARKERS = (
    "DOCKERHUB_TOKEN",
    "gh-action-pypi-publish",
    "cosign sign",
    "cosign attest",
)


def _load(name: str) -> dict[str, Any]:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def _reaches(jobs: dict[str, Any], start: str, target: str) -> bool:
    """Whether ``start`` transitively depends on ``target``."""
    seen: set[str] = set()
    stack = list(_needs(jobs.get(start, {})))
    while stack:
        name = stack.pop()
        if name == target:
            return True
        if name in seen or name not in jobs:
            continue
        seen.add(name)
        stack.extend(_needs(jobs[name]))
    return False


def _credential_jobs(name: str) -> list[str]:
    """Jobs in a workflow that touch a publishing credential or signing key."""
    doc = _load(name)
    raw = (WORKFLOWS / name).read_text(encoding="utf-8")
    # Split the raw text per job so a marker is attributed to the job it is in.
    found = []
    for job_name in doc["jobs"]:
        pattern = rf"^  {re.escape(job_name)}:$"
        match = re.search(pattern, raw, re.MULTILINE)
        assert match, job_name
        start = match.start()
        nxt = re.search(r"^  [A-Za-z0-9_-]+:$", raw[match.end() :], re.MULTILINE)
        end = match.end() + nxt.start() if nxt else len(raw)
        body = raw[start:end]
        if any(marker in body for marker in _CREDENTIAL_MARKERS):
            found.append(job_name)
    return found


# --- The gate is defined once -------------------------------------------


def test_the_tag_gate_is_a_reusable_workflow() -> None:
    doc = _load("verify-tag.yml")
    # YAML 1.1 resolves the bare key `on` to the boolean True — the same
    # coercion CL-0002 has to handle for `privileged: on`.
    triggers = doc.get("on", doc.get(True))
    assert "workflow_call" in triggers
    assert "tag" in triggers["workflow_call"]["inputs"]


def test_the_gate_performs_all_three_checks() -> None:
    """The copy in publish-channel.yml did two of three; that is what drifted."""
    raw = (WORKFLOWS / "verify-tag.yml").read_text(encoding="utf-8")
    assert "git cat-file -t" in raw, "annotated-tag check missing"
    assert "merge-base --is-ancestor" in raw, "reachable-from-main check missing"
    assert "tag -v" in raw, "signature verification missing"
    assert "allowedSignersFile" in raw


@pytest.mark.parametrize("workflow", ["publish.yml", "publish-channel.yml"])
def test_publish_paths_call_the_shared_gate(workflow: str) -> None:
    jobs = _load(workflow)["jobs"]
    assert "verify-tag" in jobs, f"{workflow} has no verify-tag job"
    assert jobs["verify-tag"].get("uses", "").endswith("verify-tag.yml"), (
        f"{workflow} defines its own gate instead of calling the shared one"
    )


@pytest.mark.parametrize("workflow", ["publish.yml", "publish-channel.yml"])
def test_no_workflow_reimplements_the_signature_check(workflow: str) -> None:
    """One definition cannot drift; two copies drift toward the weaker one."""
    raw = (WORKFLOWS / workflow).read_text(encoding="utf-8")
    assert "allowedSignersFile" not in raw, (
        f"{workflow} carries its own signature check — call verify-tag.yml"
    )


# --- Every credential-bearing job is behind it ---------------------------


@pytest.mark.parametrize("workflow", ["publish.yml", "publish-channel.yml"])
def test_credential_jobs_depend_on_the_tag_gate(workflow: str) -> None:
    jobs = _load(workflow)["jobs"]
    offenders = [
        name
        for name in _credential_jobs(workflow)
        if not _reaches(jobs, name, "verify-tag")
    ]
    assert not offenders, (
        f"{workflow}: these jobs reach a publishing credential without "
        f"depending on verify-tag: {offenders}"
    )


def test_the_credential_marker_scan_finds_something() -> None:
    """Guard the guard: an empty scan would make the test above vacuous."""
    assert _credential_jobs("publish.yml"), "no credential-bearing jobs detected"


# --- No unpinned resolution from an index we do not control --------------


def test_no_workflow_resolves_dependencies_from_an_unpinned_index() -> None:
    """`-i` makes an index *primary*, and pip prefers the highest version found.

    With TestPyPI primary, anyone who claims a dependency name there at a higher
    version supplies code into the job — and that namespace is open to any
    account. An install from such an index is only safe with ``--no-deps``,
    which scopes it to the one artifact under test.
    """
    offenders: list[str] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        # Join shell line-continuations first: a `pip install \` command spans
        # several lines, and matching per line would read only the first of
        # them — which silently makes this whole check vacuous.
        flat_file = re.sub(r"\\\s*\n\s*", " ", path.read_text(encoding="utf-8"))
        for line in flat_file.splitlines():
            if "pip install" not in line:
                continue
            uses_index = "-i http" in line or "--index-url" in line
            if uses_index and "--no-deps" not in line:
                offenders.append(f"{path.name}: {' '.join(line.split())[:110]}")
    assert not offenders, (
        "pip install resolving from a non-default index without --no-deps:\n  "
        + "\n  ".join(offenders)
    )


# --- A dispatch must not choose the code that reads a credential ---------


def test_the_dockerhub_description_dispatch_is_pinned_to_the_default_branch() -> None:
    """`workflow_dispatch` can name any ref, and `uses: ./…` runs workspace code.

    The Docker Hub secrets here are repo-level, so nothing scopes them to a ref.
    Pinning the checkout means a dispatcher chooses only *when* this runs, not
    *what* runs with a Read+Write+Delete token.
    """
    jobs = _load("dockerhub-description.yml")["jobs"]
    checkout = next(
        step
        for step in jobs["dockerhub-description"]["steps"]
        if str(step.get("uses", "")).startswith("actions/checkout")
    )
    assert checkout["with"]["ref"] == "${{ github.event.repository.default_branch }}"


def test_the_dockerhub_credential_is_only_read_by_first_party_code() -> None:
    """The token must not be handed to a third-party action."""
    raw = (WORKFLOWS / "dockerhub-description.yml").read_text(encoding="utf-8")
    for line in raw.splitlines():
        if "DOCKERHUB_TOKEN" not in line:
            continue
        # The token is passed as an input to the local composite action only.
        assert "secrets.DOCKERHUB_TOKEN" in line
    assert "uses: ./.github/actions/update-dockerhub-description" in raw
