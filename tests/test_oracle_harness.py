"""Differential test: whole generated projects, graded against Compose itself.

``test_merge_semantics`` derives the merge table from the binary and
``test_merge_fuzz`` reaches combinations of it nobody enumerated. Both work on
one overlay pair, so between them they ground the *merge* and nothing around
it. Everything a pair cannot contain — ``include:`` precedence, cross-file
``extends:``, which ``.env`` an interpolation reads, ``env_file:`` targets,
relative paths resolving against the file that wrote them — was grounded by a
probe someone ran once and wrote into a comment (#780, #796).

A comment records what the binary said on the day it was run. It does not
notice when the binary changes its mind, and it does not notice when the loader
drifts away from it. This suite generates the project directory instead, and
asks Compose on every run.

Three assertions per seed:

* **Acceptance.** Compose resolves the project — unless the seed built an
  unresolvable reference, in which case it must refuse. Asserted rather than
  skipped: "Compose rejects this" is exactly the claim that rotted in the pair
  fuzzer's ``_EXCLUSIVE`` comment (#798), and a skip would hide a generator
  that had quietly stopped producing valid projects.
* **Gap parity.** A reference compose-lint could not follow is exit 2, and the
  run must not grade the part of the stack it *could* see as if it were whole
  (A10). Conversely, a project Compose resolves must not leave a gap behind.
* **Findings parity.** The same rules over the two documents report the same
  ``(rule_id, service)`` multiset.
* **Shape parity.** Our merged document, handed back to Compose, resolves to
  the same configuration. This is what sees a field no rule reads — the case
  that let #797 ship with the finding multisets in perfect agreement — and it
  compares two Compose renderings rather than measuring ours against a
  hand-written normaliser (see ``oracle_harness/_shape.py``).
"""

from __future__ import annotations

from copy import deepcopy
from typing import TYPE_CHECKING

import pytest

from tests.oracle_harness import (
    DUMP_NAME,
    describe_difference,
    describe_shape_difference,
    findings_of,
    generate,
    lint_project,
    oracle_available,
    run_oracle,
    shape_of,
    truth_findings,
    write_dump,
)

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.skipif(
    not oracle_available(),
    reason="the oracle harness needs the docker compose CLI",
)

# Enumerated, not sampled per run. A fuzzer that generates different inputs on
# every invocation reports failures nobody can reproduce, and turns an
# unrelated commit red for reasons that vanish on re-run.
SEEDS = list(range(400))


def _replay(seed: int) -> str:
    return f"replay with: python -m tests.oracle_harness --seed {seed} --keep DIR"


@pytest.mark.parametrize("seed", SEEDS)
def test_generated_project_matches_compose(seed: int, tmp_path: Path) -> None:
    """A generated project yields the findings Compose's own resolution would."""
    project = generate(seed)
    root = tmp_path / "project"
    root.mkdir()
    primary = project.write(root)

    # Before the dump exists: it lives in the project root so that a relative
    # `env_file:` still resolves, and the truth has to be the project as
    # written.
    oracle = run_oracle(root)
    linted = lint_project(primary)
    context = f"seed {seed}\n{project.render()}\n{_replay(seed)}"

    if project.expects_gap:
        assert not oracle.accepted, (
            f"{context}\nthe unresolvable reference was resolved anyway"
        )
        assert linted.refused, (
            f"{context}\ncompose refused the project but compose-lint graded it"
        )
        return

    assert oracle.accepted, f"{context}\ncompose stderr:\n{oracle.stderr.strip()}"
    assert not linted.refused, (
        f"{context}\ncompose resolved the project; compose-lint refused it: "
        f"{linted.error or linted.gaps}"
    )

    expected = truth_findings(oracle.stdout, tmp_path / "truth")
    assert linted.findings == expected, (
        f"{context}\n{describe_difference(linted.findings, expected)}"
    )

    write_dump(linted.merged, root)
    dumped = run_oracle(root, files=(DUMP_NAME,))
    # A merged document Compose refuses is a loader defect that happens not to
    # show up as a diff — #805 arrived exactly this way, as
    # `services.web.user must be a string` on a project whose original was
    # accepted.
    assert dumped.accepted, (
        f"{context}\ncompose accepted the project and refused our merge of it:\n"
        f"{dumped.stderr.strip()}"
    )
    theirs, ours = shape_of(oracle.stdout), shape_of(dumped.stdout)
    assert ours == theirs, f"{context}\n{describe_shape_difference(theirs, ours)}"


def test_seeds_are_deterministic() -> None:
    """The same seed builds the same bytes, or a replay proves nothing."""
    assert generate(17).files == generate(17).files


def test_the_generator_reaches_every_shape_it_claims() -> None:
    """Every structural shape the seed range advertises is actually built.

    A generator whose probabilities drift can stop producing a whole class of
    project while the suite stays green — 400 seeds of the same plain pair.
    This fails when a shape falls out of the range rather than when it merely
    gets rarer.
    """
    reached = {note for seed in SEEDS for note in generate(seed).notes}
    assert reached >= {
        "include",
        "subdir-include",
        "include-own-env",
        "extends",
        "extends-own-env",
        "project-env",
        "env-file",
        "in-file-extends",
        "missing-include",
        "override",
    }


def test_the_shape_comparator_sees_what_findings_cannot(tmp_path: Path) -> None:
    """The comparator's whole justification, made falsifiable.

    A merged document that is wrong in a field no rule reads produces
    identical findings and a different resolved configuration. #797 was
    exactly that — a `depends_on` merge emitting a Python `repr`, through a
    green suite, because nothing grades `depends_on`. `labels:` is used here
    instead because Compose *accepts* a wrong label and renders it, so the
    demonstration is a shape difference rather than a rejection, and does not
    depend on any particular error text.

    Without this, a comparator that silently compared a document with itself
    would pass all 400 seeds and prove nothing.
    """
    root = tmp_path / "project"
    root.mkdir()
    (root / "compose.yaml").write_text(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.27\n"
        '    labels: {tier: "edge"}\n'
        '    ports: ["8080:80"]\n'
    )

    oracle = run_oracle(root)
    assert oracle.accepted, oracle.stderr
    linted = lint_project(root / "compose.yaml")

    broken = deepcopy(linted.merged)
    broken["services"]["web"]["labels"] = {"tier": "core"}

    # The two documents are indistinguishable to every rule...
    assert findings_of(broken, {}, root) == findings_of(linted.merged, {}, root)

    # ...and distinguishable to the comparator.
    write_dump(broken, root)
    dumped = run_oracle(root, files=(DUMP_NAME,))
    assert dumped.accepted, dumped.stderr
    assert shape_of(dumped.stdout) != shape_of(oracle.stdout)


def test_a_faithful_merge_round_trips(tmp_path: Path) -> None:
    """The other half: the comparator does not report a difference that is ours.

    Compose emits a canonical form and this project does not, so an unperturbed
    merge round-tripping proves the dump is being normalised rather than
    compared as written.
    """
    root = tmp_path / "project"
    root.mkdir()
    (root / "compose.yaml").write_text(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.27\n"
        '    ports: ["8080:80"]\n'
        '    volumes: ["./data:/data"]\n'
        '    environment: ["TIER=edge"]\n'
    )

    oracle = run_oracle(root)
    assert oracle.accepted, oracle.stderr
    linted = lint_project(root / "compose.yaml")

    write_dump(linted.merged, root)
    dumped = run_oracle(root, files=(DUMP_NAME,))
    assert dumped.accepted, dumped.stderr
    assert shape_of(dumped.stdout) == shape_of(oracle.stdout)
