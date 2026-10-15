"""`--explain` on a terminal renders the rule doc instead of dumping markdown.

Every shipped doc is rendered here, with and without color, and must leave no
markdown marker behind: a doc that reaches for syntax the renderer does not
handle fails this test rather than showing a terminal reader raw markup.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from compose_lint._terminal_markdown import render

DOCS = sorted(
    (Path(__file__).resolve().parent.parent / "docs" / "rules").glob("CL-*.md")
)
ANSI = re.compile(r"\033\[[0-9;]*m")
BOLD, CODE, DIM, RESET = "\033[1m", "\033[36m", "\033[2m", "\033[0m"

_LEFTOVERS = {
    "bold marker": re.compile(r"\*\*"),
    "link syntax": re.compile(r"\]\([^)]*\)"),
    "code fence": re.compile(r"^\s*```", re.M),
    "heading marker": re.compile(r"^#{1,6} ", re.M),
    "table rule": re.compile(r"^\s*\|?\s*-{3,}\s*\|", re.M),
    # Syntax the renderer does not handle. No rule doc uses it today; one that
    # starts to should extend the renderer rather than show the raw marker.
    "blockquote": re.compile(r"^\s*> ", re.M),
    "escaped marker": re.compile(r"\\[*_`|]"),
    "image": re.compile(r"!\["),
}


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.stem)
@pytest.mark.parametrize("color", [True, False], ids=["color", "plain"])
def test_every_rule_doc_renders_without_markdown_left_over(
    doc: Path, color: bool
) -> None:
    text = ANSI.sub("", render(doc.read_text(encoding="utf-8"), width=96, color=color))
    for name, pattern in _LEFTOVERS.items():
        assert not pattern.search(text), f"{doc.stem}: {name} left in the render"
    if color:
        # Code blocks are shown verbatim, so a backtick written inside one stays.
        prose = [line for line in text.split("\n") if not line.startswith("    ")]
        assert not any("`" in line for line in prose), (
            f"{doc.stem}: a backtick survived with color on"
        )


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.stem)
def test_prose_wraps_to_the_width(doc: Path) -> None:
    """Only a single unbreakable token (a URL, a code line) may overrun."""
    text = render(doc.read_text(encoding="utf-8"), width=80, color=False)
    for line in text.split("\n"):
        if len(line) > 80 and not line.startswith("    "):
            assert len(line.split()) <= 2 or "(http" in line, line


def test_inline_markup_becomes_styles() -> None:
    out = render("**Severity:** set `read_only: true`", width=80, color=True)
    assert out == f"{BOLD}Severity:{RESET} set {CODE}read_only: true{RESET}"


def test_without_color_code_keeps_its_backticks_and_bold_goes() -> None:
    out = render("**Severity:** set `read_only: true`", width=80, color=False)
    assert out == "Severity: set `read_only: true`"


def test_a_relative_link_keeps_its_text_and_a_web_link_its_address() -> None:
    out = render(
        "See [severity model](../severity.md) and [OWASP](https://owasp.org/x).",
        width=200,
        color=False,
    )
    assert out == "See severity model and OWASP (https://owasp.org/x)."


def test_a_list_item_wraps_under_its_text() -> None:
    out = render("- " + "word " * 30, width=40, color=False).split("\n")
    assert out[0].startswith("• word")
    assert all(line.startswith("  word") for line in out[1:])


def test_a_table_that_fits_is_lined_up() -> None:
    out = render("| a | bb |\n|---|---|\n| ccc | d |\n", width=80, color=False)
    assert out.split("\n") == ["a    bb", "───  ──", "ccc  d"]


def test_a_table_too_wide_becomes_one_record_per_row() -> None:
    row = "| " + "x " * 30 + "| " + "y " * 30 + "|"
    out = render("| Left | Right |\n|---|---|\n" + row, width=40, color=False)
    lines = out.split("\n")
    assert lines[0].startswith("Left: x x")
    assert any(line.startswith("Right: y y") for line in lines)


def test_a_code_block_is_indented_and_left_alone() -> None:
    out = render("Example:\n\n```yaml\nservices:\n  web:\n```\n", width=80, color=True)
    assert out == "Example:\n\n    services:\n      web:"


def test_a_heading_is_bold_without_its_hashes() -> None:
    assert render("## Why it matters", width=80, color=True) == (
        f"{BOLD}Why it matters{RESET}"
    )


def test_an_escaped_pipe_stays_inside_its_cell() -> None:
    out = render("| a | b |\n|---|---|\n| x \\| y | z |\n", width=80, color=False)
    assert out.split("\n")[2] == "x | y  z"
