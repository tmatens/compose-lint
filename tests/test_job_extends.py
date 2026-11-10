"""A job's ``extends:`` is resolved (ADR-040 §5, amended).

1.2.0 graded no job that used ``extends:`` and warned that the next minor
would make it a coverage gap. Resolving it retires the gap instead. Measured
on Compose 5.7.0, the version CI pins:

- an in-file ``extends: x`` or ``{service: x}`` names another **job** and
  merges as a service's does: lists append, mappings merge, chains follow,
  and a cycle or a missing target is refused;
- a job cannot extend a service in the same file ("service 'web' not found");
- a cross-file ``{file: f, service: x}`` takes ``services.x`` from ``f``, even
  when ``f`` also declares a job ``x``, and fails when ``f`` has only jobs.

The behaviour tests below hold each of those. The differential test at the
end asks a real Compose (5.6 or later, skipped without one) to resolve the
same fixtures and compares its jobs with compose-lint's.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import TYPE_CHECKING, Any

import pytest

from compose_lint.engine import run_rules
from compose_lint.parser import load_compose_full
from tests.oracle_harness import compose_argv

if TYPE_CHECKING:
    from pathlib import Path

DIGEST = "x:1@sha256:" + "0" * 64


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root / "compose.yml"


def _job(root: Path, files: dict[str, str], name: str = "child") -> Any:
    return load_compose_full(_write(root, files)).data["jobs"][name]


# --- In-file: a job extends a job ------------------------------------------

IN_FILE = """\
jobs:
  base:
    image: alpine:3.20
    user: root
    privileged: true
    environment: {A: "1"}
    cap_add: [NET_ADMIN]
    triggers: {manual: true}
  child:
    extends: base
    environment: {B: "2"}
    cap_add: [SYS_TIME]
"""


class TestInFile:
    def test_the_base_merges_in(self, tmp_path: Path) -> None:
        child = _job(tmp_path, {"compose.yml": IN_FILE})
        assert child["image"] == "alpine:3.20"
        assert child["user"] == "root"
        assert child["privileged"] is True
        assert child["environment"] == {"A": "1", "B": "2"}
        assert child["cap_add"] == ["NET_ADMIN", "SYS_TIME"]
        assert child["triggers"] == {"manual": True}

    def test_the_mapping_form_names_a_job_too(self, tmp_path: Path) -> None:
        text = IN_FILE.replace("extends: base", "extends: {service: base}")
        assert _job(tmp_path, {"compose.yml": text})["privileged"] is True

    def test_a_chain_is_followed(self, tmp_path: Path) -> None:
        text = (
            "jobs:\n"
            "  a: {image: alpine:3.20, privileged: true, triggers: {manual: true}}\n"
            "  b: {extends: a, user: root}\n"
            "  c: {extends: b}\n"
        )
        c = _job(tmp_path, {"compose.yml": text}, "c")
        assert (c["privileged"], c["user"]) == (True, "root")

    def test_reset_and_override_do_not_apply(self, tmp_path: Path) -> None:
        """Compose 5.7.0 ignores both tags in a job's `extends:` merge.

        A service child would get `cap_add: [CHOWN]` and no `cap_drop`; the
        job keeps the base's hardening and appends to its grant, and that is
        what deploys.
        """
        text = (
            "jobs:\n"
            "  base:\n    image: alpine:3.20\n    cap_add: [NET_ADMIN]\n"
            "    cap_drop: [ALL]\n    triggers: {manual: true}\n"
            "  child:\n    extends: base\n    cap_drop: !reset []\n"
            "    cap_add: !override [CHOWN]\n"
        )
        child = _job(tmp_path, {"compose.yml": text})
        assert child["cap_add"] == ["NET_ADMIN", "CHOWN"]
        assert child["cap_drop"] == ["ALL"]

    def test_a_service_and_a_job_are_resolved_independently(
        self, tmp_path: Path
    ) -> None:
        text = (
            "services:\n"
            "  base: {image: nginx:1.27, read_only: true}\n"
            "  web: {extends: base}\n"
            "jobs:\n"
            "  jbase: {image: alpine:3.20, user: root, triggers: {manual: true}}\n"
            "  child: {extends: jbase}\n"
        )
        loaded = load_compose_full(_write(tmp_path, {"compose.yml": text}))
        assert loaded.data["services"]["web"]["read_only"] is True
        assert loaded.data["jobs"]["child"]["user"] == "root"
        assert "read_only" not in loaded.data["jobs"]["child"]
        assert loaded.gaps == ()


class TestRefusals:
    """Compose refuses each of these; compose-lint reports a coverage gap."""

    @pytest.mark.parametrize(
        ("text", "reason"),
        [
            (
                "services:\n  web: {image: nginx:1.27, privileged: true}\n"
                "jobs:\n  child: {extends: web, triggers: {manual: true}}\n",
                "this file declares no job 'web'",
            ),
            (
                "jobs:\n  child: {extends: nope, image: a:1, "
                "triggers: {manual: true}}\n",
                "this file declares no job 'nope'",
            ),
            (
                "jobs:\n  a: {extends: b, image: a:1, triggers: {manual: true}}\n"
                "  b: {extends: a}\n",
                "the chain returns to a job it already inherited",
            ),
        ],
        ids=["names-a-service", "missing", "cycle"],
    )
    def test_an_unfollowable_target_is_a_gap(
        self, tmp_path: Path, text: str, reason: str
    ) -> None:
        loaded = load_compose_full(_write(tmp_path, {"compose.yml": text}))
        assert any(reason in gap for gap in loaded.gaps), loaded.gaps

    def test_the_cli_exits_2_on_it(self, tmp_path: Path) -> None:
        compose = _write(
            tmp_path,
            {
                "compose.yml": "jobs:\n  child: {extends: nope, image: "
                + DIGEST
                + ", triggers: {manual: true}}\n"
            },
        )
        proc = _cli(["--format", "json", "--fail-on", "critical", str(compose)])
        assert proc.returncode == 2, proc.stderr
        errors = json.loads(proc.stdout)["errors"]
        assert [e["kind"] for e in errors] == ["coverage_gap"]


# --- Cross-file: a job extends a service in another file ----------------------


class TestCrossFile:
    def test_the_base_is_the_other_file_s_service(self, tmp_path: Path) -> None:
        """Even when that file also declares a job of the same name."""
        child = _job(
            tmp_path,
            {
                "base.yml": "services:\n"
                "  remote: {image: nginx:1.27, read_only: true}\n"
                "jobs:\n  remote: {image: alpine:3.20, privileged: true, "
                "triggers: {manual: true}}\n",
                "compose.yml": "jobs:\n  child:\n"
                "    extends: {file: base.yml, service: remote}\n"
                "    triggers: {manual: true}\n",
            },
        )
        assert child["image"] == "nginx:1.27"
        assert child["read_only"] is True
        assert "privileged" not in child

    def test_a_file_with_only_jobs_is_a_gap(self, tmp_path: Path) -> None:
        loaded = load_compose_full(
            _write(
                tmp_path,
                {
                    "base.yml": "jobs:\n"
                    "  remote: {image: a:1, triggers: {manual: true}}\n",
                    "compose.yml": "jobs:\n  child:\n"
                    "    extends: {file: base.yml, service: remote}\n"
                    "    triggers: {manual: true}\n",
                },
            )
        )
        assert any("declares no service 'remote'" in gap for gap in loaded.gaps)

    def test_a_job_can_extend_a_job_that_extends_across_files(
        self, tmp_path: Path
    ) -> None:
        """Cross-file first, then in-file, the order services resolve in."""
        files = {
            "base.yml": "services:\n  remote: {image: nginx:1.27, privileged: true}\n",
            "compose.yml": "jobs:\n"
            "  mid:\n    extends: {file: base.yml, service: remote}\n"
            "    triggers: {manual: true}\n"
            "  child: {extends: mid, user: root}\n",
        }
        child = _job(tmp_path, files)
        assert (child["image"], child["privileged"], child["user"]) == (
            "nginx:1.27",
            True,
            "root",
        )

    def test_a_base_file_s_own_jobs_are_not_resolved(self, tmp_path: Path) -> None:
        """Opened as a service's base, a file resolves only what is inherited.

        Its jobs are not part of the project, so one whose own `extends:`
        cannot be followed is no gap here.
        """
        loaded = load_compose_full(
            _write(
                tmp_path,
                {
                    "base.yml": "services:\n  remote: {image: nginx:1.27}\n"
                    "jobs:\n  broken: {extends: missing, triggers: {manual: true}}\n",
                    "compose.yml": "services:\n  web:\n"
                    "    extends: {file: base.yml, service: remote}\n",
                },
            )
        )
        assert loaded.gaps == ()


# --- include: a job resolved by the included file is not merged twice -------


def test_an_included_job_is_merged_once(tmp_path: Path) -> None:
    """Re-resolving it in the including file would append its base again."""
    child = _job(
        tmp_path,
        {
            "inc/jobs.yml": "jobs:\n"
            "  base: {image: alpine:3.20, cap_add: [NET_ADMIN], "
            "triggers: {manual: true}}\n"
            "  child: {extends: base, cap_add: [SYS_TIME]}\n",
            "compose.yml": "include: [inc/jobs.yml]\n",
        },
    )
    assert child["cap_add"] == ["NET_ADMIN", "SYS_TIME"]


def test_an_included_job_s_file_reference_stays_its_own(tmp_path: Path) -> None:
    """Resolved against the included file's directory, and not again here.

    Re-resolving it from the including file would look for `base.yml` beside
    `compose.yml`, where there is none: a false gap.
    """
    loaded = load_compose_full(
        _write(
            tmp_path,
            {
                "inc/base.yml": "services:\n  remote: {image: nginx:1.27, "
                "privileged: true}\n",
                "inc/jobs.yml": "jobs:\n  child:\n"
                "    extends: {file: base.yml, service: remote}\n"
                "    triggers: {manual: true}\n",
                "compose.yml": "include: [inc/jobs.yml]\n",
            },
        )
    )
    assert loaded.gaps == ()
    assert loaded.data["jobs"]["child"]["privileged"] is True


# --- Grading: the extended job is a unit like any other ----------------------


class TestGrading:
    def test_an_inherited_dangerous_key_is_reported_on_the_child(
        self, tmp_path: Path
    ) -> None:
        loaded = load_compose_full(_write(tmp_path, {"compose.yml": IN_FILE}))
        privileged = {
            f.service
            for f in run_rules(loaded.data, loaded.lines)
            if f.rule_id == "CL-0002"
        }
        assert privileged == {"jobs.base", "jobs.child"}

    def test_an_inherited_line_names_the_base(self, tmp_path: Path) -> None:
        loaded = load_compose_full(_write(tmp_path, {"compose.yml": IN_FILE}))
        [child] = [
            f
            for f in run_rules(loaded.data, loaded.lines)
            if f.rule_id == "CL-0002" and f.service == "jobs.child"
        ]
        assert child.line == IN_FILE.splitlines().index("    privileged: true") + 1

    def test_inherited_hardening_is_not_reported_missing(self, tmp_path: Path) -> None:
        text = (
            "jobs:\n"
            "  base:\n    image: " + DIGEST + "\n    read_only: true\n"
            "    cap_drop: [ALL]\n    security_opt: [no-new-privileges:true]\n"
            "    triggers: {manual: true}\n"
            "  child: {extends: base, command: ['true']}\n"
        )
        loaded = load_compose_full(_write(tmp_path, {"compose.yml": text}))
        on_child = {
            f.rule_id
            for f in run_rules(loaded.data, loaded.lines)
            if f.service == "jobs.child"
        }
        base = {
            f.rule_id
            for f in run_rules(loaded.data, loaded.lines)
            if f.service == "jobs.base"
        }
        assert on_child == base

    def test_the_cli_grades_it_with_no_warning(self, tmp_path: Path) -> None:
        compose = _write(tmp_path, {"compose.yml": IN_FILE})
        proc = _cli(["--format", "json", str(compose)])
        assert proc.returncode == 1, proc.stderr
        doc = json.loads(proc.stdout)
        assert doc["warnings"] == []
        assert doc["errors"] == []
        assert "jobs.child" in {f["service"] for f in doc["findings"]}


def _cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "compose_lint", *args],
        capture_output=True,
        text=True,
        env={**os.environ, "NO_COLOR": "1"},
    )


# --- Differential: what Compose resolves is what compose-lint grades ----------


def _compose_env() -> dict[str, str]:
    """PATH, plus what decides which compose plugin runs.

    The oracle harness scrubs to PATH alone, which finds the plugin installed
    system-wide (CI's pinned one). ``DOCKER_CONFIG`` and ``HOME`` are kept so a
    local run can point at a newer plugin than the system's without changing
    what the other suites ask.
    """
    env = {"PATH": os.environ.get("PATH", "")}
    for name in ("HOME", "DOCKER_CONFIG"):
        if name in os.environ:
            env[name] = os.environ[name]
    return env


def _jobs_capable() -> bool:
    env = _compose_env()
    try:
        result = subprocess.run(
            [*compose_argv(env), "version", "--short"],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
            check=False,
        )
        major, minor = (int(part) for part in result.stdout.strip().split(".")[:2])
    except (OSError, subprocess.SubprocessError, ValueError):
        return False
    return result.returncode == 0 and (major, minor) >= (5, 6)


# Each case is a project. Every one Compose accepts must resolve every job to
# the same graded values; every one it refuses must be a gap here.
CASES: dict[str, dict[str, str]] = {
    "in-file": {"compose.yml": IN_FILE},
    "mapping-form": {
        "compose.yml": IN_FILE.replace("extends: base", "extends: {service: base}")
    },
    "chain": {
        "compose.yml": "jobs:\n"
        "  a: {image: alpine:3.20, privileged: true, cap_add: [NET_ADMIN], "
        "triggers: {manual: true}}\n"
        "  b: {extends: a, user: root, cap_add: [SYS_TIME]}\n"
        "  c: {extends: b, environment: [X=1]}\n"
    },
    "reset-override": {
        "compose.yml": "jobs:\n"
        "  base:\n    image: alpine:3.20\n    cap_add: [NET_ADMIN]\n"
        "    cap_drop: [ALL]\n    security_opt: [no-new-privileges:true]\n"
        "    triggers: {manual: true}\n"
        "  child:\n    extends: base\n    cap_drop: !reset []\n"
        "    cap_add: !override [CHOWN]\n"
    },
    "cross-file-service": {
        "base.yml": "services:\n  remote: {image: nginx:1.27, read_only: true, "
        "user: root}\n"
        "jobs:\n  remote: {image: alpine:3.20, privileged: true, "
        "triggers: {manual: true}}\n",
        "compose.yml": "jobs:\n  child:\n"
        "    extends: {file: base.yml, service: remote}\n"
        "    environment: {B: '2'}\n    triggers: {manual: true}\n",
    },
    "cross-then-in-file": {
        "base.yml": "services:\n  remote: {image: nginx:1.27, privileged: true}\n",
        "compose.yml": "jobs:\n"
        "  mid:\n    extends: {file: base.yml, service: remote}\n"
        "    triggers: {manual: true}\n"
        "  child: {extends: mid, user: root}\n",
    },
    "included": {
        "inc/jobs.yml": "jobs:\n"
        "  base: {image: alpine:3.20, cap_add: [NET_ADMIN], triggers: {manual: true}}\n"
        "  child: {extends: base, cap_add: [SYS_TIME]}\n",
        "compose.yml": "include: [inc/jobs.yml]\n",
    },
    "included-cross-file": {
        "inc/base.yml": "services:\n  remote: {image: nginx:1.27, privileged: true}\n",
        "inc/jobs.yml": "jobs:\n  child:\n"
        "    extends: {file: base.yml, service: remote}\n"
        "    triggers: {manual: true}\n",
        "compose.yml": "include: [inc/jobs.yml]\n",
    },
    "names-a-service": {
        "compose.yml": "services:\n  web: {image: nginx:1.27}\n"
        "jobs:\n  child: {extends: web, triggers: {manual: true}}\n"
    },
    "missing": {
        "compose.yml": "jobs:\n  child: {extends: nope, image: a:1, "
        "triggers: {manual: true}}\n"
    },
    "cycle": {
        "compose.yml": "jobs:\n"
        "  a: {extends: b, image: a:1, triggers: {manual: true}}\n"
        "  b: {extends: a}\n"
    },
    "cross-file-tags": {
        "base.yml": "services:\n  remote:\n    image: alpine:3.20\n"
        "    cap_add: [NET_ADMIN]\n    cap_drop: [ALL]\n",
        "compose.yml": "jobs:\n  child:\n"
        "    extends: {file: base.yml, service: remote}\n"
        "    cap_drop: !reset []\n    cap_add: !override [CHOWN]\n"
        "    triggers: {manual: true}\n",
    },
    "tag-without-extends": {
        "compose.yml": "jobs:\n  plain:\n    image: alpine:3.20\n"
        "    cap_drop: !reset [ALL]\n    triggers: {manual: true}\n"
    },
    "service-tags-unchanged": {
        "compose.yml": "services:\n"
        "  base: {image: alpine:3.20, cap_add: [NET_ADMIN], cap_drop: [ALL]}\n"
        "  child:\n    extends: base\n    cap_drop: !reset []\n"
        "    cap_add: !override [CHOWN]\n"
        "jobs:\n  j: {image: alpine:3.20, triggers: {manual: true}}\n"
    },
    "bind-in-cross-file-base": {
        "shared/base.yml": "services:\n  remote:\n    image: alpine:3.20\n"
        "    volumes: ['./cfg:/cfg:ro', '/var/run/docker.sock:/var/run/docker.sock']\n",
        "compose.yml": "jobs:\n  child:\n"
        "    extends: {file: shared/base.yml, service: remote}\n"
        "    volumes: ['./data:/data']\n    triggers: {manual: true}\n",
    },
    "environment-forms": {
        "compose.yml": "jobs:\n"
        "  a: {image: alpine:3.20, environment: [A=1, B=2], triggers: {manual: true}}\n"
        "  b: {extends: a, environment: {B: '3', C: '4'}}\n"
        "  c: {extends: b, environment: [D=5]}\n"
    },
    "cross-file-only-jobs": {
        "base.yml": "jobs:\n  remote: {image: a:1, triggers: {manual: true}}\n",
        "compose.yml": "jobs:\n  child:\n"
        "    extends: {file: base.yml, service: remote}\n"
        "    triggers: {manual: true}\n",
    },
}

# What the rules read from a job, in a form both loaders agree on once
# normalised: Compose writes `environment` as a mapping and drops an empty
# list that `!reset` leaves behind.
GRADED = ("image", "user", "privileged", "read_only", "cap_add", "cap_drop")


def _mount(entry: Any) -> tuple[str, str]:
    """A volume as (source, target), from either loader's spelling."""
    if isinstance(entry, dict):
        return str(entry.get("source", "")), str(entry["target"])
    source, target = str(entry).split(":")[:2]
    return source, target


def _graded(job: dict[str, Any]) -> dict[str, Any]:
    out = {key: job[key] for key in GRADED if key in job and job[key] not in ([], None)}
    if job.get("volumes"):
        out["volumes"] = sorted(_mount(v) for v in job["volumes"])
    for key in ("cap_add", "cap_drop", "security_opt"):
        if key in job and job[key]:
            out[key] = sorted(job[key])
    env = job.get("environment")
    if isinstance(env, list):
        env = dict(item.split("=", 1) for item in env)
    if env:
        out["environment"] = {k: str(v) for k, v in env.items()}
    return out


@pytest.mark.skipif(
    not _jobs_capable(), reason="needs a Compose that knows jobs (5.6 or later)"
)
@pytest.mark.parametrize("case", sorted(CASES))
def test_agrees_with_compose(tmp_path: Path, case: str) -> None:
    compose = _write(tmp_path, CASES[case])
    env = _compose_env()
    oracle = subprocess.run(
        [*compose_argv(env), "-f", str(compose), "config", "--format", "json"],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        env=env,
        timeout=60,
        check=False,
    )
    loaded = load_compose_full(compose)
    if oracle.returncode != 0:
        assert loaded.gaps, f"Compose refused it ({oracle.stderr.strip()}); no gap here"
        return
    assert loaded.gaps == (), loaded.gaps
    resolved = json.loads(oracle.stdout)
    for section in ("services", "jobs"):
        theirs = resolved.get(section) or {}
        ours = loaded.data.get(section) or {}
        assert sorted(ours) == sorted(theirs), section
        for name in theirs:
            assert _graded(ours[name]) == _graded(theirs[name]), f"{section}.{name}"
