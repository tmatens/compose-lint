"""Tests for the patch-coverage gate's diff and coverage-report parsers.

The gate itself is `diff-cover`; what this repo adds is the guard that stops
it passing vacuously. `diff-cover` reports "no lines" both for a diff with
nothing to measure and for a `coverage.xml` that no longer lines up with the
repo, so the guard checks that every file the report names exists here, and
— when nothing was measured — that no line the diff adds is one the report
calls a statement. A wrong parser here would make the guard itself the
silent check it exists to prevent, so each piece is tested directly. The
script lives outside the importable package, so it is loaded by path.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SCRIPT = (
    Path(__file__).resolve().parents[1] / ".github" / "scripts" / "patch-coverage.py"
)


def _load_script():
    spec = importlib.util.spec_from_file_location("_patch_coverage", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_script()


def test_hunk_lines_reads_multi_line_and_single_line_hunks():
    """A one-line hunk writes `+43`, not `+43,1`."""
    diff = (
        "diff --git a/src/compose_lint/cli.py b/src/compose_lint/cli.py\n"
        "--- a/src/compose_lint/cli.py\n"
        "+++ b/src/compose_lint/cli.py\n"
        "@@ -10,0 +11,3 @@ def main():\n"
        "+    a = 1\n"
        "+    b = 2\n"
        "+    return a + b\n"
        "@@ -40 +43 @@ def other():\n"
        "-    old()\n"
        "+    new()\n"
    )

    assert gate.parse_hunk_lines(diff) == {11, 12, 13, 43}


def test_hunk_lines_ignores_a_deletion_only_hunk():
    """`+9,0` adds nothing, so there is no new line for a test to cover."""
    diff = (
        "--- a/src/compose_lint/cli.py\n"
        "+++ b/src/compose_lint/cli.py\n"
        "@@ -10,3 +9,0 @@ def main():\n"
        "-    a = 1\n"
        "-    b = 2\n"
        "-    return a + b\n"
    )

    assert gate.parse_hunk_lines(diff) == set()


def test_hunk_lines_does_not_mistake_content_for_a_hunk_header():
    """Every content line carries a prefix, so `@@` at column 0 is a header.

    This is the property that makes per-file parsing safe. A test fixture
    that itself contains diff text would otherwise be read as structure.
    """
    diff = (
        "--- a/tests/fixtures/sample.diff\n"
        "+++ b/tests/fixtures/sample.diff\n"
        "@@ -0,0 +1,3 @@\n"
        "+@@ -100,5 +200,9 @@\n"
        "+--- a/decoy.py\n"
        "++++ b/decoy.py\n"
    )

    assert gate.parse_hunk_lines(diff) == {1, 2, 3}


def test_hunk_lines_is_empty_for_a_pure_mode_or_rename_diff():
    diff = (
        "diff --git a/src/compose_lint/old.py b/src/compose_lint/new.py\n"
        "similarity index 100%\n"
        "rename from src/compose_lint/old.py\n"
        "rename to src/compose_lint/new.py\n"
    )

    assert gate.parse_hunk_lines(diff) == set()


def test_statement_lines_reads_the_coverage_report(tmp_path: Path):
    report = tmp_path / "coverage.xml"
    report.write_text(
        "<coverage><packages><package><classes>"
        '<class filename="src/compose_lint/cli.py"><lines>'
        '<line number="11" hits="1"/><line number="13" hits="0"/>'
        "</lines></class>"
        '<class filename="src/compose_lint/engine.py"><lines>'
        '<line number="4" hits="1"/>'
        "</lines></class>"
        "</classes></package></packages></coverage>",
        encoding="utf-8",
    )

    assert gate.parse_statement_lines(report) == {
        "src/compose_lint/cli.py": {11, 13},
        "src/compose_lint/engine.py": {4},
    }


def test_missing_paths_flags_a_report_written_against_other_paths(tmp_path: Path):
    """The failure this guard exists for: nothing matches, so nothing fails.

    A report that says `compose_lint/cli.py` where the diff says
    `src/compose_lint/cli.py` matches no diff line at all, and `diff-cover`
    passes reporting exactly what a docs-only PR reports.
    """
    (tmp_path / "src" / "compose_lint").mkdir(parents=True)
    (tmp_path / "src" / "compose_lint" / "cli.py").touch()
    statements = {"compose_lint/cli.py": {11}, "src/compose_lint/cli.py": {11}}

    assert gate.missing_paths(statements, tmp_path) == ["compose_lint/cli.py"]


def test_missing_paths_is_empty_when_the_report_lines_up(tmp_path: Path):
    (tmp_path / "src" / "compose_lint").mkdir(parents=True)
    (tmp_path / "src" / "compose_lint" / "cli.py").touch()

    assert gate.missing_paths({"src/compose_lint/cli.py": {11}}, tmp_path) == []


def test_missing_paths_does_not_accept_a_directory_for_a_file(tmp_path: Path):
    (tmp_path / "src" / "compose_lint").mkdir(parents=True)

    assert gate.missing_paths({"src/compose_lint": {1}}, tmp_path) == [
        "src/compose_lint"
    ]


def test_unmeasured_statements_names_every_added_statement():
    added = {"src/compose_lint/cli.py": {11, 12, 13}}
    statements = {"src/compose_lint/cli.py": {11, 13, 20}}

    assert gate.unmeasured_statements(added, statements) == [
        "src/compose_lint/cli.py:11",
        "src/compose_lint/cli.py:13",
    ]


def test_unmeasured_statements_is_empty_for_a_comment_only_diff():
    """A comment is not a statement, so `coverage.xml` has no line for it.

    This is the case the guard must stay quiet on: `diff-cover` measuring
    nothing is the correct answer, not a broken report.
    """
    added = {"src/compose_lint/cli.py": {12}}  # the blank line and the comment
    statements = {"src/compose_lint/cli.py": {11, 13}}

    assert gate.unmeasured_statements(added, statements) == []


def test_unmeasured_statements_ignores_files_coverage_does_not_measure():
    added = {"tests/test_cli.py": {5, 6}, "docs/rules/CL-0001.md": {1}}
    statements = {"src/compose_lint/cli.py": {5, 6}}

    assert gate.unmeasured_statements(added, statements) == []
