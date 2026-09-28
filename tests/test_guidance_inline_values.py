"""A value quoted in fix guidance cannot start a line of its own.

Guidance keeps its own line breaks, and the text report indents them. A line
break inside a quoted value (an ``image:`` written with ``\\n``) used to start a
line whose whole text the Compose file chose. The runner's problem matchers keep
reading output while workflow commands are stopped, and one registered earlier
in the job (``actions/setup-python`` adds a Python traceback matcher on its own)
turned two such lines into an error annotation. :func:`inline` shows the break
as ``\\u000a`` instead.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
from pathlib import Path

import pytest

from compose_lint._output import inline
from tests._cli_env import cli_env

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES = REPO_ROOT / "src" / "compose_lint" / "rules"
MARK = "cl-guidance-inline-marker"

# actions/setup-python's .github/python.json, the two lines of its pattern.
MATCHER_FILE = re.compile(r"^\s*File\s\"(.*)\",\sline\s(\d+),\sin\s(.*)$")
MATCHER_RAISE = re.compile(r"^\s*raise\s(.*)\(\'(.*)\'\)$")


def test_inline_escapes_a_line_break() -> None:
    assert inline("a\nb") == "a\\u000ab"
    assert inline("nginx:1.27") == "nginx:1.27"
    assert inline(8080) == "8080"


@pytest.mark.parametrize(
    "repository",
    ["nginx", "nginx:1.27"],
    ids=["CL-0004-no-tag", "CL-0019-tag-no-digest"],
)
def test_a_traceback_shaped_image_matches_no_matcher(
    tmp_path: Path, repository: str
) -> None:
    (tmp_path / "compose.yml").write_text(
        "services:\n  web:\n"
        f'    image: "{repository}\\n  File \\"x.py\\", line 7, in x\\n'
        f"  raise E('{MARK}')\\ntail\"\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, "-m", "compose_lint", "compose.yml"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=cli_env(PYTHONPATH=str(REPO_ROOT / "src"), NO_COLOR="1"),
        timeout=120,
    )
    log = result.stdout + result.stderr
    assert MARK in log
    lines = log.splitlines()
    for first, second in zip(lines, lines[1:], strict=False):
        assert not (MATCHER_FILE.match(first) and MATCHER_RAISE.match(second))
    assert not any(MATCHER_RAISE.match(line) and MARK in line for line in lines)


def _guidance_root(node: ast.AST) -> ast.expr | None:
    if isinstance(node, ast.keyword) and node.arg == "fix":
        return node.value
    if isinstance(node, ast.Assign) and any(
        isinstance(t, ast.Name) and t.id in ("fix", "remedy") for t in node.targets
    ):
        return node.value
    return None


def _guidance_expressions() -> list[tuple[str, int, ast.expr]]:
    """Every value interpolated into a rule's fix text.

    That is an f-string field inside a ``fix=`` argument, or inside an
    assignment to a local that becomes one (``fix``, ``remedy``).
    """
    found = []
    for path in sorted(RULES.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        roots = [
            root
            for node in ast.walk(tree)
            if (root := _guidance_root(node)) is not None
        ]
        for root in roots:
            for field in ast.walk(root):
                if isinstance(field, ast.FormattedValue):
                    found.append((path.name, field.lineno, field.value))
    return found


def test_every_value_in_fix_text_goes_through_inline() -> None:
    expressions = _guidance_expressions()
    assert expressions, "the scan found no interpolated guidance at all"
    unwrapped = [
        f"{name}:{line}: {ast.unparse(value)}"
        for name, line, value in expressions
        if not (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "inline"
        )
        # A local that is itself built with inline() (CL-0013's remedy).
        and not (isinstance(value, ast.Name) and value.id == "remedy")
    ]
    assert unwrapped == []
