"""What counts as "a Compose file" is defined in three places (#622).

``COMPOSE_FILENAMES`` in ``_selection``, a hand-copied bash list in ``action.yml``,
and a regex in ``.pre-commit-hooks.yaml``. A user who moves between surfaces
expects the same repository to lint the same way, and nothing held the three
together.

The two relationships are deliberately different, so they are asserted
differently:

* **The action must match the CLI exactly.** Its list is a duplicate of a
  list that lives in Python — it exists only because ``steps[].uses`` cannot
  call into the package. A duplicate that is allowed to differ is just a bug
  with a delay on it, and the action is the surface most users meet first.

* **The hook may be broader, and is.** pre-commit hands it a filename-filtered
  changeset, so matching ``compose.prod.yml`` is the useful behavior there,
  whereas bare ``compose-lint`` must not guess which of a repository's files
  are Compose files. What must not happen is the hook *missing* something the
  CLI would lint — that direction is a user losing coverage on the surface
  they trust most, and it is what these tests pin.

Whether the CLI's default set should itself grow (``compose.override.yml`` is
the obvious candidate, since Compose merges it automatically) is a product
question, not a consistency one. It is deliberately not decided here.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from compose_lint._selection import COMPOSE_FILENAMES

REPO_ROOT = Path(__file__).resolve().parent.parent
ACTION = REPO_ROOT / "action.yml"
HOOKS = REPO_ROOT / ".pre-commit-hooks.yaml"

# Names the hook selects and the CLI/action deliberately do not. Each is a
# real spelling a user would write, and each is currently linted by the hook
# and invisible to `compose-lint` with no arguments.
BROADER_THAN_CLI = [
    "compose.prod.yml",
    "docker-compose.override.yml",
    "compose.dev.yaml",
    "nested/compose.yml",
]


def _action_default_filenames() -> set[str]:
    """The filename list in action.yml's discovery step."""
    action = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    step = next(s for s in action["runs"]["steps"] if s.get("id") == "find-files")
    # The step has two `for f in …` loops: one over $CL_FILES (the explicit
    # `files:` input) and one over the literal default names. Select on the
    # absence of a variable rather than on position, and require the choice
    # to be unambiguous — matching the wrong loop would compare this list
    # against something that is not a filename list at all.
    loops = [
        operand
        for operand in re.findall(r"for f in ([^;]+); do", step["run"])
        if "$" not in operand
    ]
    assert len(loops) == 1, (
        f"expected exactly one literal filename loop in action.yml, found {loops}"
    )
    return set(loops[0].split())


def _hook() -> dict[str, Any]:
    hooks = yaml.safe_load(HOOKS.read_text(encoding="utf-8"))
    return next(h for h in hooks if h["id"] == "compose-lint")


def _hook_selects(path: str) -> bool:
    hook = _hook()
    files = re.compile(hook.get("files", ""))
    exclude = re.compile(hook.get("exclude", "^$"))
    return bool(files.search(path)) and not exclude.search(path)


def test_the_action_list_is_recognisable() -> None:
    """Guard the guard: a silent extraction failure would pass everything."""
    assert _action_default_filenames(), "extracted no filenames from action.yml"


def test_the_action_default_matches_the_cli_exactly() -> None:
    """A hand-copied duplicate is a bug with a delay on it.

    If ``COMPOSE_FILENAMES`` gains an entry, the action keeps the old list
    silently — and reports "no Compose files found" on a repository the CLI
    lints happily.
    """
    assert _action_default_filenames() == set(COMPOSE_FILENAMES), (
        "action.yml's default discovery list has drifted from "
        "_selection.py's COMPOSE_FILENAMES; they are the same contract"
    )


@pytest.mark.parametrize("name", COMPOSE_FILENAMES)
def test_the_hook_selects_everything_the_cli_would_lint(name: str) -> None:
    """The hook must never be narrower than the CLI.

    Broader is a documented choice; narrower means a user's pre-commit run
    passes over a file their CI run fails on.
    """
    assert _hook_selects(name), f"the pre-commit hook would skip {name}"
    assert _hook_selects(f"nested/{name}"), f"the hook would skip nested/{name}"


@pytest.mark.parametrize("name", BROADER_THAN_CLI)
def test_the_documented_divergence_is_still_exactly_this(name: str) -> None:
    """The hook is broader than the CLI, on purpose — pin how much.

    Listing the divergence beats asserting it away: if one of these ever
    starts being linted by bare ``compose-lint`` too, that is a deliberate
    change to the CLI's default set and this test is where it gets noticed
    (and where docs/configuration.md gets updated).
    """
    assert _hook_selects(name), f"the hook no longer selects {name}"
    assert name not in COMPOSE_FILENAMES
    assert name not in _action_default_filenames()
