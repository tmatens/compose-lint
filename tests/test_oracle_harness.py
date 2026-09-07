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

What it cannot see: a field no rule reads, merged to the wrong value, with the
multisets agreeing — which is how #797 shipped. That is the shape comparator's
job, and it is not here yet.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tests.oracle_harness import (
    describe_difference,
    generate,
    lint_project,
    oracle_available,
    run_oracle,
    truth_findings,
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
