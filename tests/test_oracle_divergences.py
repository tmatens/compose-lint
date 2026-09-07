"""The deliberate differences, asserted to still be differences.

``tests/test_oracle_harness.py`` asserts that compose-lint and Compose agree.
A handful of disagreements are policy rather than defect, each decided in an
ADR or an issue, and they need somewhere to live that is not a suppression.

Every entry records both halves — what Compose does, and what this project
does instead — and this suite asserts both still hold. That is the part that
matters. A divergence nobody re-checks is a comment, and a comment claiming a
difference that has since closed is worse than none: it justifies behaviour on
a premise that stopped being true. If Compose changes to match us, the entry
fails here rather than becoming folklore.

The registry itself, with the reasoning, is
``tests/oracle_harness/_divergences.py``.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from compose_lint.parser import ComposeError, load_compose_full
from tests.oracle_harness import (
    DIVERGENCES,
    Divergence,
    generate,
    oracle_available,
    run_oracle,
)
from tests.oracle_harness._divergences import registered_names
from tests.test_oracle_harness import SEEDS

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from tests.oracle_harness import GeneratedProject

needs_oracle = pytest.mark.skipif(
    not oracle_available(),
    reason="the divergence registry needs the docker compose CLI",
)


def _write(divergence: Divergence, root: Path) -> Path:
    for relative, text in divergence.files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    # The last file written is the one the run is pointed at, and every fixture
    # names it last so the project root is unambiguous.
    return root / next(reversed(divergence.files))


@needs_oracle
@pytest.mark.parametrize("divergence", DIVERGENCES, ids=registered_names)
def test_divergences_are_still_divergences(
    divergence: Divergence, tmp_path: Path
) -> None:
    """Compose still does its half, and compose-lint still does the other."""
    primary = _write(divergence, tmp_path)
    where = f"{divergence.name} ({divergence.reference})"

    oracle = run_oracle(
        primary.parent,
        all_profiles=divergence.all_profiles,
        environment=divergence.environment or None,
    )
    assert oracle.accepted, f"{where}: compose refused the fixture\n{oracle.stderr}"
    for shown in divergence.compose_shows:
        assert shown in oracle.stdout, (
            f"{where}: compose no longer {divergence.compose_does} — "
            f"{shown!r} is gone from its output, so this may have stopped "
            f"being a divergence:\n{oracle.stdout}"
        )
    for hidden in divergence.compose_hides:
        assert hidden not in oracle.stdout, (
            f"{where}: compose now emits {hidden!r}, so it may have stopped "
            f"{divergence.compose_does}:\n{oracle.stdout}"
        )

    try:
        loaded = load_compose_full(primary)
    except ComposeError as exc:
        assert divergence.ours_refuses, (
            f"{where}: compose-lint refused the fixture unexpectedly: {exc}"
        )
        return
    assert not divergence.ours_refuses, (
        f"{where}: compose-lint was recorded as refusing this and did not"
    )

    assert bool(loaded.gaps) == divergence.ours_gap, (
        f"{where}: expected coverage gap={divergence.ours_gap}, got {loaded.gaps}"
    )
    rendered = repr(loaded.data)
    for shown in divergence.ours_shows:
        assert shown in rendered, f"{where}: {shown!r} missing from {rendered}"
    for hidden in divergence.ours_hides:
        assert hidden not in rendered, f"{where}: {hidden!r} present in {rendered}"


def test_every_divergence_names_a_decision() -> None:
    """A divergence with no decision behind it is a bug that was written down."""
    for divergence in DIVERGENCES:
        assert divergence.reference, divergence.name
        assert divergence.compose_does and divergence.we_do, divergence.name


# --- What the harness therefore does not cover ------------------------------
#
# The generator builds none of the projects above, by construction. That is a
# gap in coverage, and it has to be a visible one: without these checks the 400
# agreeing seeds would be consistent both with "the loader agrees with Compose"
# and with "the generator steers around the places it does not", and only the
# first is a claim worth making.


def _interpolation_always_defaults(project: GeneratedProject) -> None:
    for name, text in project.files.items():
        for match in re.finditer(r"\$\{([^}]*)\}", text):
            assert ":-" in match.group(1), (
                f"seed {project.seed}: {name} writes {match.group(0)} with no "
                "default, which is a registered divergence rather than a case"
            )


def _no_reference_leaves_the_project(project: GeneratedProject) -> None:
    for name, text in project.files.items():
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("- ") and stripped.endswith((".yaml", ".yml")):
                assert not stripped[2:].startswith(("..", "/")), (
                    f"seed {project.seed}: {name} references {stripped[2:]}"
                )


def _no_profiles(project: GeneratedProject) -> None:
    for name, text in project.files.items():
        assert "profiles:" not in text, f"seed {project.seed}: {name}"


def _one_document_per_file(project: GeneratedProject) -> None:
    for name, text in project.files.items():
        assert "\n---" not in text, f"seed {project.seed}: {name}"


GENERATOR_AVOIDS: dict[str, Callable[[GeneratedProject], None]] = {
    "shell-environment-fallback": _interpolation_always_defaults,
    "reference-defined-nowhere": _interpolation_always_defaults,
    "include-outside-the-project": _no_reference_leaves_the_project,
    "profiled-service-under-a-default-run": _no_profiles,
    "multi-document-stream": _one_document_per_file,
}


def test_every_registered_divergence_says_how_the_generator_avoids_it() -> None:
    """A new entry cannot be added without saying what keeps it out of the seeds.

    Otherwise the registry and the generator drift apart silently: an entry
    lands, the generator starts producing that shape anyway, and the harness
    reports a policy difference as a loader disagreement.
    """
    assert set(GENERATOR_AVOIDS) == {d.name for d in DIVERGENCES}


@pytest.mark.parametrize("name", sorted(GENERATOR_AVOIDS))
def test_the_generator_avoids_every_registered_divergence(name: str) -> None:
    """No seed builds a project whose answer is settled policy."""
    check = GENERATOR_AVOIDS[name]
    for seed in SEEDS:
        check(generate(seed))
