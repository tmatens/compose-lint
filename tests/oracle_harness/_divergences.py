"""Where compose-lint answers differently from Compose, on purpose.

The harness asserts agreement. Some disagreements are policy, decided in an
ADR, and will never close — so they need somewhere to live that is not a
suppression. This is that place, and the shape is deliberately the one
``test_env_semantics.DIVERGENT`` already uses: each entry records what Compose
does, what this project does instead, and why, and the suite asserts that
**both halves still hold**.

That last part is the whole point. A divergence nobody re-checks is a comment,
and a comment claiming a difference that has since closed is worse than no
comment: it justifies behaviour on a premise that is no longer true. If Compose
ever changes to match us, the entry fails here rather than quietly becoming
folklore.

Each entry is a fixture rather than a predicate over generated projects,
because the generator deliberately does not build any of these — it always
gives an interpolation reference a default, never points a reference outside
the project, and never declares a profile. ``test_the_generator_avoids_every
_registered_divergence`` pins that, so the 400 agreeing seeds mean the loader
agrees rather than that the generator steered around the places it does not.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Divergence:
    """One deliberate difference, and the observations that prove it is still one."""

    name: str
    # The ADR or issue that decided it. A divergence with no decision behind it
    # is a bug that has been written down.
    reference: str
    # Prose for a reader, not asserted.
    compose_does: str
    we_do: str
    # The fixture, relative path -> text.
    files: dict[str, str]
    # Substrings that must (and must not) appear in Compose's resolved output.
    compose_shows: tuple[str, ...] = ()
    compose_hides: tuple[str, ...] = ()
    # The same for our merged document, rendered with `repr`.
    ours_shows: tuple[str, ...] = ()
    ours_hides: tuple[str, ...] = ()
    # compose-lint refuses the document outright (exit 2, a parse error).
    ours_refuses: bool = False
    # compose-lint reports at least one coverage gap (exit 2).
    ours_gap: bool = False
    # Variables the oracle is allowed to see. Empty everywhere except the one
    # entry whose subject is the shell environment.
    environment: dict[str, str] = field(default_factory=dict)
    # Ask Compose what a *default* run resolves, rather than every profile.
    all_profiles: bool = True


_BASE = "services:\n  web:\n    image: nginx:1.27\n"


DIVERGENCES: tuple[Divergence, ...] = (
    Divergence(
        name="shell-environment-fallback",
        reference="ADR-026",
        compose_does="substitutes a name defined only in the invoking shell",
        we_do=(
            "leaves the reference as written: its value is a fact about the "
            "machine that ran the lint, not about the project, and a finding "
            "derived from it would not reproduce on the deploy host"
        ),
        files={"compose.yaml": "services:\n  web:\n    image: nginx:${SHELL_ONLY}\n"},
        environment={"SHELL_ONLY": "from-shell"},
        compose_shows=("nginx:from-shell",),
        ours_shows=("${SHELL_ONLY}",),
    ),
    Divergence(
        name="reference-defined-nowhere",
        reference="ADR-026",
        compose_does="substitutes empty, shipping `image: 'nginx:'`",
        we_do=(
            "leaves the reference as written rather than grading a value the "
            "document does not build"
        ),
        files={"compose.yaml": "services:\n  web:\n    image: nginx:${NOWHERE}\n"},
        compose_shows=("nginx:'",),
        ours_shows=("${NOWHERE}",),
    ),
    Divergence(
        name="include-outside-the-project",
        reference="ADR-036 §7",
        compose_does="reads the file and merges the services it declares",
        we_do=(
            "refuses to read it and reports a coverage gap, so the run says "
            "part of the stack was not linted instead of grading it against a "
            "file whose contents are a fact about the lint host's filesystem"
        ),
        files={
            "outer/common.yaml": "services:\n  shared:\n    image: nginx:1.27\n",
            "project/compose.yaml": ("include:\n  - ../outer/common.yaml\n" + _BASE),
        },
        compose_shows=("shared:",),
        ours_hides=("shared",),
        ours_gap=True,
    ),
    Divergence(
        name="profiled-service-under-a-default-run",
        reference="#659",
        compose_does="drops a profiled service unless its profile is enabled",
        we_do=(
            "grades it anyway: whether a profile is on is a property of the "
            "command someone will run later, and a linter that stays silent "
            "about `privileged: true` because it is behind a profile has "
            "cleared a container that does get started"
        ),
        files={
            "compose.yaml": (
                "services:\n"
                "  web:\n"
                "    image: nginx:1.27\n"
                "  tools:\n"
                "    image: nginx:1.27\n"
                "    profiles: [debug]\n"
                "    privileged: true\n"
            )
        },
        all_profiles=False,
        compose_hides=("tools:",),
        ours_shows=("tools",),
    ),
    Divergence(
        name="multi-document-stream",
        reference="ADR-003",
        compose_does="accepts the stream and merges every document in it",
        we_do=(
            "refuses the file. A `---` separator in a Compose file is far more "
            "often a copy-paste accident than an intent, and the loader has no "
            "way to tell; refusing says so rather than silently grading a "
            "merge nobody wrote"
        ),
        files={
            "compose.yaml": (
                "services:\n"
                "  web:\n"
                "    image: nginx:1.27\n"
                "---\n"
                "services:\n"
                "  two:\n"
                "    image: nginx:1.27\n"
            )
        },
        compose_shows=("two:",),
        ours_refuses=True,
    ),
)

# Deliberately not duplicated here: a malformed line in a `.env` (Compose
# refuses the whole file, a lint run skips the line and continues) already has
# an entry in `test_env_semantics.DIVERGENT`, asserted the same way. One
# divergence, one home.


def registered_names(divergence: Divergence) -> str:
    """Parametrisation id: the entry's own name, so a failure says which."""
    return divergence.name
