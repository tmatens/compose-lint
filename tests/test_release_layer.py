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


# --- A called workflow gets what its jobs ask for ------------------------

# GITHUB_TOKEN permission levels, ordered. Under an explicit `permissions:`
# map, any scope not listed is `none` — that is what makes a deny-all default
# and a partial map behave the same way for an unlisted scope.
_LEVELS = {"none": 0, "read": 1, "write": 2}
_LEVEL_NAME = {v: k for k, v in _LEVELS.items()}


def _permission_levels(spec: Any) -> tuple[dict[str, int], int]:
    """Explicit per-scope levels, and the level every unlisted scope gets."""
    if spec == "read-all":
        return {}, _LEVELS["read"]
    if spec == "write-all":
        return {}, _LEVELS["write"]
    if isinstance(spec, dict):
        return {k: _LEVELS[v] for k, v in spec.items()}, _LEVELS["none"]
    raise AssertionError(f"unrecognised permissions form: {spec!r}")


def _reusable_calls() -> list[tuple[str, str, str]]:
    """(caller workflow, caller job, callee workflow) for every local call."""
    calls = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for job_name, job in (_load(path.name).get("jobs") or {}).items():
            uses = str(job.get("uses", ""))
            if uses.startswith("./.github/workflows/"):
                calls.append((path.name, job_name, uses.rsplit("/", 1)[-1]))
    return calls


@pytest.mark.parametrize(("caller", "job_name", "callee"), _reusable_calls())
def test_a_called_workflow_is_granted_what_its_jobs_request(
    caller: str, job_name: str, callee: str
) -> None:
    """A called workflow's jobs cannot hold more than the calling job was given.

    Ask for more and GitHub rejects the *whole run*: no job is created, so
    there is no log, no annotation and no check-run to read — the reason exists
    only as UI text on the run page. The v0.18.0 tag push died exactly this way.
    ``publish.yml`` declared ``permissions: {}`` workflow-wide and nothing on
    the job calling ``verify-tag.yml``, whose job asks for ``contents: read`` to
    check out, so the release failed to start.

    This is invisible to the other gates. ``actionlint`` does not model
    permission inheritance across a workflow call, and the pipeline itself only
    runs on a tag push — which is after the point of no return.
    """
    caller_doc = _load(caller)
    caller_job = caller_doc["jobs"][job_name]
    granted = caller_job.get("permissions", caller_doc.get("permissions"))
    assert granted is not None, (
        f"{caller}: job '{job_name}' calls {callee} but neither it nor the "
        f"workflow declares `permissions:`, so the grant is whatever the "
        f"repository default happens to be. Declare it explicitly."
    )
    granted_map, granted_default = _permission_levels(granted)

    callee_doc = _load(callee)
    for callee_job, spec in (callee_doc.get("jobs") or {}).items():
        requested = spec.get("permissions", callee_doc.get("permissions"))
        if requested is None:
            continue
        req_map, req_default = _permission_levels(requested)

        short = []
        if req_default > granted_default:
            short.append(
                f"unlisted scopes (needs {_LEVEL_NAME[req_default]}, "
                f"granted {_LEVEL_NAME[granted_default]})"
            )
        for scope in sorted(set(req_map) | set(granted_map)):
            needs = req_map.get(scope, req_default)
            has = granted_map.get(scope, granted_default)
            if needs > has:
                short.append(
                    f"{scope} (needs {_LEVEL_NAME[needs]}, granted {_LEVEL_NAME[has]})"
                )

        assert not short, (
            f"{caller} job '{job_name}' does not grant {callee} job "
            f"'{callee_job}' what it requests: {'; '.join(short)}. "
            f"The run would fail to start with no job, log or annotation."
        )


def test_the_reusable_call_scan_finds_something() -> None:
    """Guard the guard: an empty scan would make the check above vacuous."""
    assert _reusable_calls(), "no reusable-workflow calls detected"


# --- Smoke fixtures: one copy, or they drift (#624) -----------------------


def _run_scripts() -> list[tuple[str, str]]:
    """Every ``run:`` script in every workflow, as (workflow, script)."""
    scripts: list[tuple[str, str]] = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in (workflow.get("jobs") or {}).values():
            for step in job.get("steps") or []:
                run = step.get("run")
                if isinstance(run, str):
                    scripts.append((path.name, run))
    return scripts


def test_no_workflow_inlines_a_compose_document() -> None:
    """Smoke fixtures live in tests/smoke/, and nowhere else.

    ``tests/smoke/clean.yml`` exists because the fixture once lived in five
    heredocs and only some of them included ``tmpfs:``. That consolidation
    missed all five: ci.yml's docker-smoke was still grading the pre-0.3.x
    document, and publish-channel.yml carried four more copies (#624). A
    comment naming the participating workflows had been wrong for as long
    as it existed, because nothing checked it.

    A duplicated fixture is not a style problem. It is a surface being
    graded against a definition of "insecure" that no longer matches the
    one every other surface uses, reporting success either way.
    """
    offenders = [
        name
        for name, script in _run_scripts()
        if re.search(r"^\s*services:\s*$", script, re.MULTILINE)
    ]
    assert not offenders, (
        "workflow run: blocks contain an inline Compose document "
        f"({sorted(set(offenders))}). Mount tests/smoke/*.yml instead — see #624."
    )


def test_the_shared_fixtures_are_actually_consumed() -> None:
    """Guard the guard: the check above passes trivially if nothing uses them."""
    consumers = {name for name, script in _run_scripts() if "tests/smoke/" in script}
    assert len(consumers) >= 3, (
        f"only {sorted(consumers)} reference tests/smoke/ — the no-inline-fixture "
        "check above would pass vacuously if the fixtures fell out of use"
    )


# --- The pre-publish smoke is one definition, not two (#633) --------------

_SHARED_DOCKER_SMOKE = "release-docker-smoke.yml"


@pytest.mark.parametrize("workflow", ["publish.yml", "publish-channel.yml"])
def test_publish_paths_call_the_shared_docker_smoke(workflow: str) -> None:
    """Both publish paths smoke the image with the same steps, or one drifts.

    publish-channel.yml is dispatch-only and last ran in April, so its copy of
    the battery was never executed — edits to it were checked by reading and by
    actionlint, and nothing else. It had already lost a check the normal path
    ran: publish.yml asserted the container emits valid SARIF and the emergency
    path did not, so the escape hatch graded the image against a smaller
    definition of "works" than every normal release used.

    A `uses:` job cannot carry `steps:`, so this also makes the drift
    impossible to reintroduce by hand rather than merely detectable.
    """
    job = _load(workflow)["jobs"]["docker-smoke"]
    assert job.get("uses", "").endswith(_SHARED_DOCKER_SMOKE), (
        f"{workflow}: docker-smoke defines its own battery instead of calling "
        f"{_SHARED_DOCKER_SMOKE} — the emergency path is the one nothing runs"
    )
    assert "steps" not in job, (
        f"{workflow}: docker-smoke calls the shared smoke but also carries its "
        "own steps"
    )


def test_the_shared_docker_smoke_keeps_its_whole_battery() -> None:
    """Sharing stops the paths diverging; it does not stop both losing a check.

    With one definition a dropped assertion is invisible in review — every
    caller still "runs the smoke". Pin what the battery asserts, the same way
    tests/smoke/insecure.golden.json pins what a surface must report.
    """
    doc = _load(_SHARED_DOCKER_SMOKE)
    steps = doc["jobs"]["docker-smoke"]["steps"]
    names = [str(step.get("name", "")) for step in steps]
    for expected in ("version output", "clean fixture", "insecure fixture", "SARIF"):
        assert any(expected in name for name in names), (
            f"{_SHARED_DOCKER_SMOKE} no longer asserts '{expected}'; every "
            f"publish path lost that check at once. Steps: {names}"
        )


def test_the_shared_docker_smoke_runs_the_documented_hardened_flags() -> None:
    """The smoke runs README.md's copy-paste recipe, so a broken one fails CI.

    These flags exist to prove the hardening users are told to apply still
    works against the shipped image. A smoke that quietly dropped, say,
    ``--read-only`` would keep passing while the documented recipe broke.
    """
    raw = (WORKFLOWS / _SHARED_DOCKER_SMOKE).read_text(encoding="utf-8")
    docker_runs = raw.count("docker run --rm")
    for flag in (
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges:true",
        "--network none",
        "--user 65532:65532",
        "--pids-limit 256",
    ):
        assert raw.count(flag) == docker_runs, (
            f"{_SHARED_DOCKER_SMOKE}: '{flag}' appears {raw.count(flag)} times "
            f"across {docker_runs} `docker run` invocations — every smoke step "
            "runs the fully-hardened flag set documented in README.md"
        )


# --- The 1.0 classifier bump has no second chance --------------------------


def test_the_development_status_classifier_matches_the_major_version() -> None:
    """PyPI metadata is immutable per version, so a miss is permanent.

    `docs/RELEASING.md` says to flip `4 - Beta` to `5 - Production/Stable` in
    the same commit that sets `version = "1.0.0"`. That was prose with nothing
    enforcing it: nothing in `tests/`, `scripts/` or `.github/workflows/`
    referenced the classifier, so 1.0.0 could publish permanently labelled
    Beta and the only remedy would be 1.0.1.
    """
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version = re.search(r'^version = "([^"]+)"', text, re.M)
    assert version, "could not read version from pyproject.toml"
    major = int(version.group(1).split(".")[0])

    classifiers = re.findall(r'"(Development Status :: [^"]+)"', text)
    assert len(classifiers) == 1, f"expected one status classifier, got {classifiers}"
    status = classifiers[0]

    if major >= 1:
        assert status == "Development Status :: 5 - Production/Stable", (
            f"version is {version.group(1)} but the classifier is {status!r}. "
            "PyPI metadata is immutable per version — flip this in the same "
            "commit that sets the version (docs/RELEASING.md)."
        )
    else:
        assert status == "Development Status :: 4 - Beta", (
            f"version is {version.group(1)}, so the classifier should still be "
            f"'4 - Beta', not {status!r}."
        )
