"""No output path lets file text issue a CI command (GHSA-r7j4-crjv-h467).

The 0.31.0 fix escaped ``##[`` and a line-leading ``::`` in the text report and
on stderr. Four routes were left:

- the runner finds "the start of a line" after .NET ``TrimStart()``, which
  strips every Unicode white-space character, while the sanitizer allowed only
  space and tab before ``::``;
- ``--format json`` and ``--format sarif`` on stdout never passed through the
  sanitizer;
- argparse echoed a rejected argument, such as a repository path handed over
  without ``--``, straight to stderr;
- Azure Pipelines acts on ``##vso[`` anywhere in a line, which nothing escaped.

``tests/_workflow_commands.py`` is the GitHub runner model. Its line-start test
is Python's ``str.strip()``, a superset of .NET's white space, which
:func:`test_the_model_strips_what_the_runner_strips` pins.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from compose_lint._output import defuse_json, emit, sanitize, sanitize_line
from tests._cli_env import cli_env
from tests._workflow_commands import forged, processed

REPO_ROOT = Path(__file__).resolve().parent.parent
MARK = "cl-p4-residue-marker"

# Every character .NET's Char.IsWhiteSpace accepts, which is what String.TrimStart()
# with no arguments removes: the Unicode space separators, the line and
# paragraph separators, and U+0009-U+000D and U+0085.
DOTNET_WHITESPACE = [
    "\t",
    "\x0b",
    "\x0c",
    "\r",
    " ",
    "\x85",
    "\xa0",
    " ",
    *(chr(c) for c in range(0x2000, 0x200B)),
    " ",
    " ",
    " ",
    " ",
    "　",
]


def _ids(chars: list[str]) -> list[str]:
    return [f"U+{ord(c):04X}" for c in chars]


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "compose_lint", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=cli_env(PYTHONPATH=str(REPO_ROOT / "src"), NO_COLOR="1"),
        timeout=120,
    )


def _no_command(log: str) -> None:
    assert forged(log, MARK) == []
    assert "##vso[" not in log.lower()


# --- The line-start class ---------------------------------------------------


@pytest.mark.parametrize("space", DOTNET_WHITESPACE, ids=_ids(DOTNET_WHITESPACE))
def test_the_model_strips_what_the_runner_strips(space: str) -> None:
    """Otherwise a test passes over a prefix the runner would strip."""
    assert processed(f"{space}::notice::{MARK}") != []


@pytest.mark.parametrize("space", DOTNET_WHITESPACE, ids=_ids(DOTNET_WHITESPACE))
@pytest.mark.parametrize("escape", [sanitize, sanitize_line])
def test_any_white_space_before_a_line_leading_command_is_defused(
    space: str, escape: Any
) -> None:
    for text in (
        f"{space}::notice::{MARK}",
        f"fix:\n{space}{space}::notice::{MARK}",
        f"fix:\n   {space}::notice::{MARK}",
    ):
        _no_command(escape(text))


@pytest.mark.parametrize("space", ["\xa0", "　", " ", " "])
def test_emit_continuations_are_defused(
    space: str, capsys: pytest.CaptureFixture[str]
) -> None:
    emit(f"note: first\n{space}::notice::{MARK}")
    _no_command(capsys.readouterr().err)


@pytest.mark.parametrize(
    "text",
    ["ports: ::1:8080:80", "a::b", "x\xa0y", "\xa0indented", "## heading"],
)
def test_text_that_is_not_a_command_is_unchanged(text: str) -> None:
    assert sanitize(text) == text


# --- Azure's opener ---------------------------------------------------------


@pytest.mark.parametrize(
    "opener", ["##vso[", "##VSO[", "##Vso["], ids=["lower", "upper", "mixed"]
)
@pytest.mark.parametrize("escape", [sanitize, sanitize_line])
def test_the_azure_opener_is_defused_anywhere(opener: str, escape: Any) -> None:
    out = escape(f"service a{opener}task.setvariable variable={MARK}]x")
    assert opener not in out
    assert MARK in out


# --- JSON on stdout ---------------------------------------------------------


def test_defuse_json_keeps_the_document_identical() -> None:
    value = {
        "service": f"a##[warning]{MARK}",
        "azure": f"b##vso[task.x]{MARK}",
        "list": ["##[", "[##]", "x##[y"],
        "slash": "\\##[",
    }
    text = defuse_json(json.dumps(value, indent=2))
    assert json.loads(text) == value
    _no_command(text)
    assert "##[" not in text


# --- End to end, one per route ---------------------------------------------


@pytest.mark.parametrize("space", ["\xa0", "　", " "], ids=_ids(["\xa0", "　", " "]))
def test_the_text_reports_fix_guidance(tmp_path: Path, space: str) -> None:
    """CL-0019's fix line starts with the image value, so a newline in it puts
    the rest at the start of a line."""
    (tmp_path / "compose.yml").write_text(
        f'services:\n  web:\n    image: "nginx\\n{space}::notice::{MARK}"\n',
        encoding="utf-8",
    )
    result = _run(["compose.yml"], tmp_path)
    log = result.stdout + result.stderr
    assert MARK in log
    _no_command(log)


def test_the_fix_dry_run_diff(tmp_path: Path) -> None:
    """A diff quotes source lines, and a quoted scalar can continue onto a
    line of its own that starts with a no-break space."""
    (tmp_path / "compose.yml").write_text(
        "services:\n  web:\n    labels:\n"
        f'      - "x\n       \xa0::notice::{MARK}"\n'
        "    image: nginx:1.27\n",
        encoding="utf-8",
    )
    result = _run(["fix", "compose.yml"], tmp_path)
    log = result.stdout + result.stderr
    assert MARK in log
    _no_command(log)


def test_a_config_rule_key_on_stderr(tmp_path: Path) -> None:
    (tmp_path / "compose.yml").write_text(
        "services:\n  web:\n    image: nginx:1.27\n", encoding="utf-8"
    )
    (tmp_path / ".compose-lint.yml").write_text(
        f'rules:\n  "CL-9999\\n\xa0::notice::{MARK}":\n    enabled: false\n',
        encoding="utf-8",
    )
    result = _run(["compose.yml"], tmp_path)
    assert MARK in result.stderr
    _no_command(result.stdout + result.stderr)


@pytest.mark.parametrize("fmt", ["json", "sarif"])
def test_json_and_sarif_on_stdout(tmp_path: Path, fmt: str) -> None:
    (tmp_path / "compose.yml").write_text(
        "services:\n"
        f'  "a##[warning]{MARK}":\n    image: nginx:latest\n'
        f'  "b##vso[task.setvariable variable=x]{MARK}":\n    image: nginx:latest\n',
        encoding="utf-8",
    )
    result = _run(["--format", fmt, "compose.yml"], tmp_path)
    _no_command(result.stdout + result.stderr)
    assert "##[" not in result.stdout
    document = json.loads(result.stdout)
    assert f"a##[warning]{MARK}" in json.dumps(document, ensure_ascii=False)


def test_an_argument_argparse_rejects(tmp_path: Path) -> None:
    """A repository directory handed over with no ``--`` before it."""
    (tmp_path / "compose.yml").write_text(
        "services:\n  web:\n    image: nginx:1.27\n", encoding="utf-8"
    )
    for argument in (
        f"--##[warning]{MARK}/compose.yml",
        f"--x\n\xa0::warning::{MARK}",
        f"--##vso[task.x]{MARK}",
    ):
        result = _run([argument], tmp_path)
        assert result.returncode == 2
        assert MARK in result.stderr
        _no_command(result.stdout + result.stderr)


# The report's file heading and per-file summary, and fix's summary line,
# start with the path as given, so a repository directory's name starts them.
FILE_NAME_SPACES = ["\xa0", "\u2028", "\u3000", " "]


@pytest.mark.skipif(
    sys.platform == "win32", reason="Windows forbids ':' in a file name"
)
@pytest.mark.parametrize("space", FILE_NAME_SPACES, ids=_ids(FILE_NAME_SPACES))
@pytest.mark.parametrize(
    "command",
    [[], ["--quiet"], ["fix"], ["fix", "--apply"]],
    ids=["heading-and-summary", "quiet-summary", "fix-summary", "apply-summary"],
)
def test_a_file_name_at_the_start_of_a_line(
    tmp_path: Path, space: str, command: list[str]
) -> None:
    directory = tmp_path / f"{space}::notice::{MARK}"
    directory.mkdir()
    (directory / "compose.yml").write_text(
        "services:\n  web:\n    image: nginx:latest\n    privileged: true\n",
        encoding="utf-8",
    )
    result = _run([*command, "--", f"{directory.name}/compose.yml"], tmp_path)
    log = result.stdout + result.stderr
    assert MARK in log
    _no_command(log)


@pytest.mark.parametrize(
    "argv",
    [
        [f"--x\r::notice::{MARK}/compose.yml"],
        ["--format", f"x\r::notice::{MARK}", "compose.yml"],
    ],
    ids=["unrecognized-argument", "invalid-choice"],
)
def test_a_carriage_return_in_an_argument_argparse_echoes(
    tmp_path: Path, argv: list[str]
) -> None:
    """The runner also ends a line at a lone carriage return. Captured as bytes,
    because text mode would turn it into a newline before the check."""
    (tmp_path / "compose.yml").write_text(
        "services:\n  web:\n    image: nginx:1.27\n", encoding="utf-8"
    )
    result = subprocess.run(
        [sys.executable, "-m", "compose_lint", *argv],
        cwd=tmp_path,
        capture_output=True,
        env=cli_env(PYTHONPATH=str(REPO_ROOT / "src"), NO_COLOR="1"),
        timeout=120,
    )
    assert result.returncode == 2
    # Windows ends every line with CRLF itself; only a bare CR is the file's.
    assert b"\r" not in (result.stdout + result.stderr).replace(b"\r\n", b"\n")
    log = (result.stdout + result.stderr).decode("utf-8")
    assert MARK in log
    _no_command(log)


def test_help_still_reaches_stdout(tmp_path: Path) -> None:
    result = _run(["check", "--help"], tmp_path)
    assert result.returncode == 0
    assert "--fail-on" in result.stdout
    assert result.stderr == ""
