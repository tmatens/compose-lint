"""Differential test: do we resolve each substitution operator as Compose does?

Compose has six substitution operators and they differ along two axes: whether
they substitute when the variable is *unset* (``:-``/``-``) or when it is *set*
(``:+``/``+``), and whether a leading colon makes an *empty* value count as
unset. Six spellings times three states of the variable is eighteen answers, and
they are not derivable from the Compose documentation with enough confidence to
hand-write — issue #664 was exactly a case where the plausible reading was wrong
and a ``${BIND:?required}`` resolving to ``0.0.0.0`` reached the rules as source
text.

So this asks the binary, on every run, rather than pinning a table someone
transcribed once. A Compose release that changes an operator fails here instead
of silently mis-resolving a user's stack.

The variable is supplied by a sibling ``.env``, which is the case ADR-026 put in
scope; the ambient shell stays out of it.

Skipped when the ``docker compose`` CLI is unavailable, so the suite still runs
in environments without it.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest
import yaml

from compose_lint._env_file import parse_env
from compose_lint.rules._interpolation import substitute_defaults

if TYPE_CHECKING:
    from pathlib import Path


def _compose_cli_works() -> bool:
    """Whether ``docker compose`` can actually run, not merely whether it exists."""
    if shutil.which("docker") is None:
        return False
    try:
        return (
            subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True,
                timeout=30,
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


pytestmark = pytest.mark.skipif(
    not _compose_cli_works(),
    reason="differential interpolation test needs a working docker compose CLI",
)

_COMPOSE = """\
services:
  s:
    image: i
    environment:
      OUT: "%s"
"""

# The six operators, written against a variable named V.
OPERATORS = ["${V:-DEF}", "${V-DEF}", "${V:?err}", "${V?err}", "${V:+ALT}", "${V+ALT}"]

# The three states a sibling `.env` can leave V in. An absent V is spelled with
# an unrelated key so the file itself is still valid.
STATES = {"set": "V=hello", "empty": "V=", "absent": "OTHER=x"}

# Cases where Compose refuses the project outright. There is no configuration to
# grade, so the only correct answer is "unresolved".
REFUSED = {
    ("${V:?err}", "empty"),
    ("${V:?err}", "absent"),
    ("${V?err}", "absent"),
}

# Cases where Compose ships a value and we deliberately decline to, with the
# reason. Listed here so the split is visible in one place rather than being an
# unexplained gap in coverage.
DIVERGENT = {
    ("${V:+ALT}", "absent"): (
        "Compose ships empty because nothing set V, but ADR-026 does not model "
        "the ambient shell, so a name absent from .env is not knowably unset -- "
        "the same call made for a bare ${VAR}."
    ),
    ("${V+ALT}", "absent"): (
        "Same as ${V:+ALT} with V absent: knowing the alternate does not ship "
        "requires knowing nothing outside the .env set V."
    ),
}


def _compose_resolves(directory: Path, expression: str, env_text: str) -> str | None:
    """Ground truth: what Compose substitutes for ``expression``.

    ``None`` means Compose refused the file, which is a real answer for the
    ``REFUSED`` cases rather than a broken fixture.
    """
    (directory / "compose.yml").write_text(
        _COMPOSE % expression, encoding="utf-8", newline=""
    )
    (directory / ".env").write_text(env_text, encoding="utf-8", newline="")
    result = subprocess.run(
        ["docker", "compose", "config"],
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        return None
    document = yaml.safe_load(result.stdout)
    # `config` prints a literal `$` as `$$` so its output round-trips through
    # Compose's own interpolation; compare the value, not the serialisation.
    return str(document["services"]["s"]["environment"]["OUT"]).replace("$$", "$")


def _ours(expression: str, env_text: str) -> str | None:
    return substitute_defaults(expression, parse_env(env_text, ["V"]).values)


@pytest.mark.parametrize("state", sorted(STATES))
@pytest.mark.parametrize("expression", OPERATORS)
def test_operator_matches_compose(expression: str, state: str, tmp_path: Path) -> None:
    """Every operator resolves to what Compose ships, or declines for a reason."""
    theirs = _compose_resolves(tmp_path, expression, STATES[state])
    ours = _ours(expression, STATES[state])

    if (expression, state) in REFUSED:
        assert theirs is None, (
            f"{expression} with V {state} was expected to be refused by Compose, "
            f"but it shipped {theirs!r} -- move it out of REFUSED"
        )
        assert ours is None, (
            f"{expression} with V {state}: Compose refuses the project, so there "
            f"is nothing to grade, but we resolved it to {ours!r}"
        )
        return

    assert theirs is not None, f"compose refused an unexpected fixture: {expression}"

    if (expression, state) in DIVERGENT:
        assert ours is None, (
            f"{expression} with V {state} is recorded as a divergence "
            f"({DIVERGENT[(expression, state)]}) but we resolved it to {ours!r}. "
            "If that is now intended, move it out of DIVERGENT."
        )
        return

    assert ours == theirs, (
        f"disagreement for {expression} with V {state}: "
        f"compose ships {theirs!r}, we ship {ours!r}"
    )


def test_required_operator_resolves_a_supplied_value(tmp_path: Path) -> None:
    """The regression from #664, end to end.

    ``${BIND:?required}`` with a ``.env`` supplying BIND is the plain reference
    ``${BIND}``; the error text applies only when it is unset. Reading only the
    default operators left the value fetched and discarded, so CL-0005 could not
    see the ``0.0.0.0`` Compose publishes on.
    """
    theirs = _compose_resolves(tmp_path, "${BIND:?required}", "BIND=0.0.0.0")
    assert theirs == "0.0.0.0"
    assert substitute_defaults("${BIND:?required}", {"BIND": "0.0.0.0"}) == "0.0.0.0"
