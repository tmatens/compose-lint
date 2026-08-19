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
