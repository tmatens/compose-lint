"""Guard: `src/` must not re-introduce a second definition of "a line".

The line-space desync was not a typo — it was two modules each deciding for
themselves what a line break is. ``compose_lint._lines`` is now the single
authority, and this test keeps it that way: a future ``text.splitlines()`` in
``src/`` silently reintroduces the divergence (``str.splitlines()`` breaks on
five codepoints PyYAML does not), and nothing else in the suite would catch it
until a fixer spliced the wrong bytes again.

Fix a failure by importing ``split_lines`` from ``compose_lint._lines``.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "compose_lint"

# The module that *owns* the definition is allowed to implement it.
_EXEMPT = {"_lines.py"}


def _split_lines_calls(tree: ast.AST) -> list[int]:
    """Line numbers of every ``<expr>.splitlines(...)`` call in ``tree``."""
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "splitlines"
    ]


def test_no_bare_splitlines_in_src() -> None:
    offenders: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name in _EXEMPT:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for lineno in _split_lines_calls(tree):
            offenders.append(f"{path.relative_to(SRC.parent.parent)}:{lineno}")

    assert not offenders, (
        "str.splitlines() found in src/ — use compose_lint._lines.split_lines() "
        "so the fix engine, the fixers and the parser share one line space:\n  "
        + "\n  ".join(offenders)
    )


def test_the_guard_can_actually_see_a_call() -> None:
    """Guard the guard: prove the AST matcher fires on a known-bad snippet."""
    tree = ast.parse("def f(t):\n    return t.splitlines(keepends=True)\n")
    assert _split_lines_calls(tree) == [2]
