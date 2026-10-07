"""publish.yml's workflow_dispatch republish path, exercised without running it.

A republish is rare by design, so its job graph would otherwise be checked by
reading and nothing else, the failure the old manual publish workflow kept
demonstrating (#633). These tests evaluate every job's ``if:`` the way the
Actions runner does, over push and dispatch scenarios, and pin which jobs run.

One piece of runner behaviour is not pinned down by GitHub's documentation:
whether a job's implicit ``success()`` looks at its direct needs only, or at
every ancestor. Each scenario is evaluated under both readings and must come
out the same, so the result does not hinge on which one GitHub implements.

The ref guard in verify-tag.yml is executed for real, with the environment a
dispatch from the wrong ref would give it.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"

# --- A minimal evaluator for the expression subset publish.yml uses --------

_TOKEN = re.compile(
    r"\s*(?:(?P<op>&&|\|\||==|!=|!|\(|\)|,)|'(?P<str>[^']*)'|(?P<name>[A-Za-z_][\w.-]*))"
)
_STATUS_FUNCTIONS = ("success(", "failure(", "always(", "cancelled(")


def _tokens(expr: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pos = 0
    expr = expr.strip()
    while pos < len(expr):
        match = _TOKEN.match(expr, pos)
        assert match and match.end() > pos, f"cannot parse {expr[pos:]!r}"
        kind = match.lastgroup
        assert kind is not None
        out.append((kind, match.group(kind)))
        pos = match.end()
    return out


class _Eval:
    def __init__(self, expr: str, ctx: dict[str, Any], status: dict[str, bool]) -> None:
        self.toks = _tokens(expr)
        self.i = 0
        self.ctx = ctx
        self.status = status

    def _peek(self) -> tuple[str, str] | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _take(self, value: str | None = None) -> tuple[str, str]:
        tok = self.toks[self.i]
        assert value is None or tok[1] == value, f"expected {value!r}, got {tok!r}"
        self.i += 1
        return tok

    def run(self) -> Any:
        value = self._or()
        assert self.i == len(self.toks), f"trailing tokens {self.toks[self.i :]}"
        return value

    def _or(self) -> Any:
        value = self._and()
        while self._peek() == ("op", "||"):
            self._take()
            rhs = self._and()
            value = value or rhs
        return value

    def _and(self) -> Any:
        value = self._not()
        while self._peek() == ("op", "&&"):
            self._take()
            rhs = self._not()
            value = value and rhs
        return value

    def _not(self) -> Any:
        if self._peek() == ("op", "!"):
            self._take()
            return not self._not()
        return self._cmp()

    def _cmp(self) -> Any:
        lhs = self._primary()
        tok = self._peek()
        if tok in (("op", "=="), ("op", "!=")):
            self._take()
            rhs = self._primary()
            equal = str(lhs).lower() == str(rhs).lower()
            return equal if tok[1] == "==" else not equal
        return lhs

    def _primary(self) -> Any:
        kind, value = self._take()
        if (kind, value) == ("op", "("):
            inner = self._or()
            self._take(")")
            return inner
        if kind == "str":
            return value
        assert kind == "name", f"unexpected {value!r}"
        if self._peek() == ("op", "("):
            self._take()
            args: list[Any] = []
            while self._peek() != ("op", ")"):
                args.append(self._or())
                if self._peek() == ("op", ","):
                    self._take()
            self._take(")")
            return self._call(value, args)
        return self._lookup(value)

    def _call(self, name: str, args: list[Any]) -> Any:
        if name in self.status:
            return self.status[name]
        if name == "startsWith":
            return str(args[0]).lower().startswith(str(args[1]).lower())
        raise AssertionError(f"evaluator does not implement {name}()")

    def _lookup(self, dotted: str) -> Any:
        node: Any = self.ctx
        for part in dotted.split("."):
            assert isinstance(node, dict) and part in node, f"unknown context {dotted}"
            node = node[part]
        return node


def _condition(job: dict[str, Any]) -> str:
    raw = str(job.get("if", "")).strip()
    if raw.startswith("${{") and raw.endswith("}}"):
        raw = raw[3:-2].strip()
    return " ".join(raw.split())


def _needs(job: dict[str, Any]) -> list[str]:
    needs = job.get("needs", [])
    return [needs] if isinstance(needs, str) else list(needs)


def simulate(
    event: str,
    fail: frozenset[str] = frozenset(),
    *,
    ancestors: bool,
    ref: str = "v1.4.0",
) -> dict[str, str]:
    """Each job's result: 'success', 'failure', or 'skipped'.

    ``ancestors`` picks the implicit-success() reading: all ancestors when
    True, direct needs only when False.
    """
    jobs = yaml.safe_load((WORKFLOWS / "publish.yml").read_text(encoding="utf-8"))[
        "jobs"
    ]
    results: dict[str, str] = {}

    def ancestry(name: str) -> set[str]:
        seen: set[str] = set()
        stack = _needs(jobs[name])
        while stack:
            dep = stack.pop()
            if dep not in seen:
                seen.add(dep)
                stack.extend(_needs(jobs[dep]))
        return seen

    def resolve(name: str) -> str:
        if name in results:
            return results[name]
        direct = _needs(jobs[name])
        for dep in direct:
            resolve(dep)
        scope = ancestry(name) if ancestors else set(direct)
        all_ok = all(results[d] == "success" for d in scope)
        expr = _condition(jobs[name])
        ctx = {
            "github": {"event_name": event, "ref_name": ref, "ref": f"refs/tags/{ref}"},
            "needs": {d: {"result": results[d]} for d in direct},
        }
        status = {
            "success": all_ok,
            "failure": False,
            "always": True,
            "cancelled": False,
        }
        if not expr:
            runs = all_ok
        elif any(fn in expr for fn in _STATUS_FUNCTIONS):
            runs = bool(_Eval(expr, ctx, status).run())
        else:
            runs = all_ok and bool(_Eval(expr, ctx, status).run())
        results[name] = (
            ("failure" if name in fail else "success") if runs else "skipped"
        )
        return results[name]

    for name in jobs:
        resolve(name)
    return results


def ran(
    event: str, fail: frozenset[str] = frozenset(), ref: str = "v1.4.0"
) -> set[str]:
    """Jobs that run, asserting both implicit-success() readings agree."""
    direct = simulate(event, fail, ancestors=False, ref=ref)
    every = simulate(event, fail, ancestors=True, ref=ref)
    assert direct == every, (
        "outcome depends on how the runner reads implicit success(): "
        f"{ {k: (direct[k], every[k]) for k in direct if direct[k] != every[k]} }"
    )
    return {name for name, result in direct.items() if result != "skipped"}


DOCKER_PATH = {
    "verify-tag",
    "docker-smoke",
    "docker-scout",
    "release-gate",
    "docker-build",
    "docker-publish",
}
PUSH_ONLY = {
    "build",
    "testpypi",
    "testpypi-smoke",
    "publish",
    "dockerhub-description",
    "create-release",
    "verify-release-signatures",
    "bump-marketplace-smoke-pin",
    "action-major-tag",
}


class TestPush:
    def test_a_release_runs_every_job(self) -> None:
        assert ran("push") == DOCKER_PATH | PUSH_ONLY

    def test_v0_release_skips_only_the_major_tag(self) -> None:
        assert ran("push", ref="v0.35.0") == (DOCKER_PATH | PUSH_ONLY) - {
            "action-major-tag"
        }

    def test_failed_gate_runs_nothing(self) -> None:
        assert ran("push", frozenset({"verify-tag"})) == {"verify-tag"}

    def test_failed_build_stops_the_docker_side_too(self) -> None:
        assert ran("push", frozenset({"build"})) == {"verify-tag", "build"}

    @pytest.mark.parametrize(
        "smoke", ["testpypi-smoke", "docker-smoke", "docker-scout"]
    )
    def test_any_failed_smoke_holds_the_release_gate(self, smoke: str) -> None:
        jobs = ran("push", frozenset({smoke}))
        assert "release-gate" not in jobs
        assert not jobs & {"publish", "docker-build", "docker-publish"}

    def test_a_skipped_smoke_holds_the_release_gate(self) -> None:
        # A failed TestPyPI upload leaves its smoke *skipped*, not failed. The
        # gate accepts that skip on a dispatch only; on a push it must hold.
        jobs = ran("push", frozenset({"testpypi"}))
        assert not jobs & {"testpypi-smoke", "release-gate", "publish", "docker-build"}


class TestDispatch:
    def test_republish_runs_the_docker_path_only(self) -> None:
        assert ran("workflow_dispatch") == DOCKER_PATH

    def test_republish_still_needs_the_release_gate(self) -> None:
        assert "release-gate" in ran("workflow_dispatch")

    def test_failed_gate_runs_nothing(self) -> None:
        assert ran("workflow_dispatch", frozenset({"verify-tag"})) == {"verify-tag"}

    @pytest.mark.parametrize("smoke", ["docker-smoke", "docker-scout"])
    def test_failed_smoke_holds_the_release_gate(self, smoke: str) -> None:
        jobs = ran("workflow_dispatch", frozenset({smoke}))
        assert not jobs & {"release-gate", "docker-build", "docker-publish"}

    def test_failed_build_leg_publishes_nothing(self) -> None:
        assert "docker-publish" not in ran(
            "workflow_dispatch", frozenset({"docker-build"})
        )

    def test_rejected_approval_publishes_nothing(self) -> None:
        jobs = ran("workflow_dispatch", frozenset({"release-gate"}))
        assert not jobs & {"docker-build", "docker-publish"}


def test_the_evaluator_reads_every_condition() -> None:
    """Guard the guard: a job condition the evaluator skipped would pass vacuously."""
    jobs = yaml.safe_load((WORKFLOWS / "publish.yml").read_text(encoding="utf-8"))[
        "jobs"
    ]
    conditioned = {name for name, job in jobs.items() if _condition(job)}
    assert conditioned >= {"build", "docker-smoke", "release-gate", "docker-build"}
    assert set(jobs) == DOCKER_PATH | PUSH_ONLY, "a job was added; classify it above"


def test_dispatch_takes_no_inputs() -> None:
    """The tag comes from the ref the run is on, never from a typed input."""
    doc = yaml.safe_load((WORKFLOWS / "publish.yml").read_text(encoding="utf-8"))
    triggers = doc["on"] if "on" in doc else doc[True]
    assert "workflow_dispatch" in triggers
    assert not (triggers["workflow_dispatch"] or {}).get("inputs")


# --- The ref guard, executed --------------------------------------------------


def _guard_script() -> str:
    doc = yaml.safe_load((WORKFLOWS / "verify-tag.yml").read_text(encoding="utf-8"))
    steps = doc["jobs"]["verify-tag"]["steps"]
    guard = next(
        s for s in steps if s.get("name") == "Assert the run is on this release tag"
    )
    assert steps.index(guard) == 0, "the ref guard must run before anything else"
    return str(guard["run"])


@pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")
@pytest.mark.parametrize(
    ("tag", "ref", "passes"),
    [
        ("v1.4.0", "refs/tags/v1.4.0", True),
        ("v0.35.0", "refs/tags/v0.35.0", True),
        ("main", "refs/heads/main", False),
        ("v1.4.0", "refs/heads/v1.4.0", False),  # a branch named like the tag
        ("v1.4.0", "refs/tags/v1.3.0", False),
        ("v1", "refs/tags/v1", False),  # the moving major tag
        ("v1.4.0-rc1", "refs/tags/v1.4.0-rc1", False),
    ],
)
def test_ref_guard(tag: str, ref: str, passes: bool) -> None:
    proc = subprocess.run(
        ["bash", "-e", "-c", _guard_script()],
        env={"TAG": tag, "GITHUB_REF": ref, "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert (proc.returncode == 0) == passes, proc.stdout + proc.stderr
