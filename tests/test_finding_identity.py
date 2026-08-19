"""A finding's identity must not be its prose (ADR-024).

``_partial_fingerprints`` is what GitHub uses to match an alert across
commits and to deduplicate uploads. It used to digest the finding's
*message*, because the message carries the specific offending value and
that is what distinguishes two hits of one rule on one service.

The cost was that prose became API. Rewording a message — fixing a typo,
clarifying a sentence — changed the digest, and GitHub closed every
affected alert and opened a new one in its place. A docs improvement was
a breaking change, silently.

The identity is now ``(file, rule, service, evidence)``, where
``evidence`` is the offending value as structured data. That leaves one
obligation, and it is the one this module enforces: a rule that can fire
more than once for a single service **must** set ``evidence``, or its
findings collide into a single alert and the others vanish from Code
Scanning.
"""

from __future__ import annotations

import ast
import collections
import pathlib

import pytest

from compose_lint.engine import run_rules
from compose_lint.formatters.sarif import _partial_fingerprints
from compose_lint.parser import loads

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURE_DIRS = [REPO_ROOT / "tests"]


def _fixtures() -> list[pathlib.Path]:
    found: list[pathlib.Path] = []
    for root in FIXTURE_DIRS:
        for pattern in ("*.yml", "*.yaml"):
            found.extend(sorted(root.rglob(pattern)))
    return found


def _documents() -> list[tuple[pathlib.Path, list]]:
    docs = []
    for path in _fixtures():
        try:
            data, lines = loads(path.read_text(encoding="utf-8"), base_dir=path.parent)
            findings = run_rules(data, lines)
        except Exception:  # noqa: BLE001 - non-Compose fixtures are not the subject
            continue
        if findings:
            docs.append((path, findings))
    return docs


def test_the_fixture_sweep_finds_something() -> None:
    """Guard the guard: an empty sweep would make the checks below vacuous."""
    docs = _documents()
    assert len(docs) >= 20, f"only {len(docs)} fixture documents produced findings"


def test_no_two_findings_in_one_document_share_a_fingerprint() -> None:
    """The obligation evidence exists to satisfy.

    A collision is not cosmetic: GitHub treats one fingerprint as one
    alert, so the second finding is not shown at all. A rule that grew a
    second per-service finding without evidence would silently hide it.
    """
    offenders: dict[str, list[str]] = collections.defaultdict(list)
    for path, findings in _documents():
        seen: dict[str, list] = collections.defaultdict(list)
        for f in findings:
            digest = _partial_fingerprints(str(path), f)["composeLintFinding/v2"]
            seen[digest].append(f)
        for collided in seen.values():
            if len(collided) > 1:
                rule = collided[0].rule_id
                offenders[rule].append(
                    f"{path.name}: service={collided[0].service!r} "
                    f"x{len(collided)} (evidence={[c.evidence for c in collided]})"
                )
    assert not offenders, (
        "these rules can fire more than once per service and must set "
        "Finding.evidence to stay distinguishable:\n"
        + "\n".join(f"  {r}: {v[0]}" for r, v in sorted(offenders.items()))
    )


def test_rewording_a_message_does_not_change_the_fingerprint() -> None:
    """The whole point: prose is no longer part of the identity."""
    docs = _documents()
    path, findings = docs[0]
    original = findings[0]
    reworded = type(original)(
        **{
            **{f: getattr(original, f) for f in original.__dataclass_fields__},
            "message": original.message + " (clarified wording)",
        }
    )
    assert _partial_fingerprints(str(path), original) == _partial_fingerprints(
        str(path), reworded
    )


def test_changing_the_evidence_does_change_the_fingerprint() -> None:
    """...and the structured identity still discriminates."""
    docs = _documents()
    path, findings = docs[0]
    original = findings[0]
    altered = type(original)(
        **{
            **{f: getattr(original, f) for f in original.__dataclass_fields__},
            "evidence": (original.evidence or "") + "-different",
        }
    )
    assert _partial_fingerprints(str(path), original) != _partial_fingerprints(
        str(path), altered
    )


@pytest.mark.parametrize("field", ["rule_id", "service"])
def test_the_remaining_identity_components_still_discriminate(field: str) -> None:
    docs = _documents()
    path, findings = docs[0]
    original = findings[0]
    altered = type(original)(
        **{
            **{f: getattr(original, f) for f in original.__dataclass_fields__},
            field: str(getattr(original, field)) + "-x",
        }
    )
    assert _partial_fingerprints(str(path), original) != _partial_fingerprints(
        str(path), altered
    )


# --- The static guard: coverage must not depend on fixtures (#632 review) ---


def _rule_modules() -> list[pathlib.Path]:
    return sorted((REPO_ROOT / "src" / "compose_lint" / "rules").glob("CL*.py"))


def _finding_calls_inside_loops(tree: ast.AST) -> list[ast.Call]:
    """Every ``Finding(...)`` construction that sits inside a loop.

    A construction under ``for``/``while`` can run more than once per
    service, which is exactly the condition that requires ``evidence``.
    """
    found: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            continue
        for inner in ast.walk(node):
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Name)
                and inner.func.id == "Finding"
            ):
                found.append(inner)
    return found


def _sets_evidence(call: ast.Call) -> bool:
    return any(kw.arg == "evidence" for kw in call.keywords)


@pytest.mark.parametrize("module", _rule_modules(), ids=lambda p: p.stem)
def test_a_rule_that_can_fire_twice_sets_evidence(module: pathlib.Path) -> None:
    """Structural, because the fixture sweep only sees what fixtures cover.

    The sweep below is honest about what it observes and blind to what it
    does not: when this guard was first written, no fixture put two socket
    mounts on one service, so CL-0001 — the tool's flagship CRITICAL —
    shipped colliding into a single alert while the sweep stayed green.
    CL-0013, CL-0017 and CL-0022 were wrong the same way.

    Reading the source instead removes the dependency on someone having
    imagined the right fixture. If a rule constructs a Finding inside a
    loop, it can fire more than once per service, and its findings need
    distinguishing whether or not a fixture happens to prove it.

    A rule that legitimately cannot repeat despite looping (the loop picks
    one winner and breaks, say) should still pass ``evidence`` — it costs
    nothing and keeps this check free of exceptions to argue about.
    """
    tree = ast.parse(module.read_text(encoding="utf-8"))
    offenders = [c for c in _finding_calls_inside_loops(tree) if not _sets_evidence(c)]
    assert not offenders, (
        f"{module.name} builds a Finding inside a loop at line(s) "
        f"{[c.lineno for c in offenders]} without evidence=. It can fire more "
        "than once per service, and GitHub shows one alert per fingerprint — "
        "so the others would never appear. See ADR-024."
    )


def test_the_static_guard_actually_inspects_rules() -> None:
    """Guard the guard: a broken glob or parser would pass everything."""
    modules = _rule_modules()
    assert len(modules) >= 20, f"only found {len(modules)} rule modules"
    with_loops = [
        m for m in modules if _finding_calls_inside_loops(ast.parse(m.read_text()))
    ]
    assert len(with_loops) >= 10, (
        f"only {len(with_loops)} rules appear to build Findings in loops — "
        "the AST matcher has probably stopped matching"
    )


# --- Evidence derivations are a contract, not an implementation detail ------

# Exact evidence each rule must derive, on the fixture below. Changing a
# value here re-keys that rule's alerts for every consumer, so it has to be
# a deliberate, reviewed edit rather than a side effect of refactoring the
# rule. Normalized forms on purpose: rewriting `SYS_ADMIN` as
# `CAP_SYS_ADMIN`, or reordering a ports list, is the same configuration and
# must keep the same alert.
EVIDENCE_CONTRACT = {
    "CL-0001": {"/var/run/docker.sock", "/run/containerd/containerd.sock"},
    "CL-0005": {"8080:80", "3000"},
    "CL-0009": {"apparmor", "seccomp"},
    "CL-0010": {"pid", "ipc"},
    "CL-0011": {"NET_ADMIN"},
    "CL-0013": {"/etc"},
    "CL-0016": {"/dev/sda"},
    "CL-0022": {"/c1", "/c2"},
    "CL-0024": {"SYS_ADMIN"},
    "CL-0027": {"SYS_PTRACE"},
    "CL-0029": {"SYS_NICE"},
}

_CONTRACT_DOC = """
services:
  sink:
    image: x:1
    ports: ["8080:80", "3000"]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /run/containerd/containerd.sock:/s2:ro
      - /etc:/host-etc:ro
    tmpfs: ["/c1:exec", "/c2:suid"]
    devices:
      - /dev/sda:/dev/sda
    cap_add: [SYS_ADMIN, NET_ADMIN, SYS_NICE, SYS_PTRACE]
    security_opt: ["apparmor:unconfined", "seccomp:unconfined"]
    pid: host
    ipc: host
"""


def _contract_evidence() -> dict[str, set[str]]:
    data, lines = loads(_CONTRACT_DOC)
    got: dict[str, set[str]] = collections.defaultdict(set)
    for f in run_rules(data, lines):
        if f.evidence is not None:
            got[f.rule_id].add(f.evidence)
    return got


@pytest.mark.parametrize("rule_id", sorted(EVIDENCE_CONTRACT))
def test_evidence_derivation_is_pinned(rule_id: str) -> None:
    """A refactor must not silently re-key a rule's alerts.

    ``evidence`` is the alert's identity, so the expression a rule derives
    it from is a consumer-facing contract even though it never appears in
    the output. Without this, tidying a rule's internals could change every
    fingerprint it produces — a partial, unannounced repeat of the v1 -> v2
    transition this design exists to make unnecessary (ADR-024).
    """
    got = _contract_evidence()
    assert got.get(rule_id) == EVIDENCE_CONTRACT[rule_id], (
        f"{rule_id} evidence changed: expected {sorted(EVIDENCE_CONTRACT[rule_id])}, "
        f"got {sorted(got.get(rule_id, []))}. If deliberate, this re-keys that "
        "rule's Code Scanning alerts — say so in the CHANGELOG's Upgrading note."
    )


def test_evidence_is_normalized_not_as_written() -> None:
    """Cosmetic rewrites of the same config must keep the same alert."""
    variants = [
        "    cap_add: [SYS_ADMIN]\n",
        "    cap_add: [CAP_SYS_ADMIN]\n",
        "    cap_add: [cap_sys_admin]\n",
    ]
    seen = set()
    for cap in variants:
        doc = "services:\n  s:\n    image: x:1\n" + cap
        data, lines = loads(doc)
        seen.update(
            f.evidence for f in run_rules(data, lines) if f.rule_id == "CL-0024"
        )
    assert len(seen) == 1, f"the same capability derived {len(seen)} evidences: {seen}"
