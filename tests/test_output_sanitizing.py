"""Externally-derived text must not be able to write compose-lint's report.

Everything the tool prints about a Compose file is attacker-authored to some
degree — service names, image refs, parse-error text quoting the document,
source excerpts read off disk. Sanitizing used to be a private helper inside
the text formatter, so it covered the formatter's own fields and nothing else:
26 other print sites emitted the same class of text raw, and the ``fix``
dry-run diff — the surface a human reads before authorising a write — printed
file content verbatim.

The escaping now lives in ``compose_lint._output`` and every stderr write goes
through :func:`~compose_lint._output.emit`, so it is the default rather than
something each new call site must remember. ``test_no_raw_stderr_writes``
enforces that.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

from compose_lint._output import sanitize, sanitize_line
from tests._cli_env import cli_env

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src" / "compose_lint"

ESC = "\x1b"
RLO = "\u202e"
ZWSP = "\u200b"


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "compose_lint", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=cli_env(PYTHONPATH=str(REPO_ROOT / "src"), NO_COLOR="1"),
        timeout=120,
    )


# --- The two escaping levels ----------------------------------------------


def test_sanitize_escapes_controls_and_bidi_but_keeps_layout() -> None:
    assert sanitize(f"a{ESC}b") == "a\\u001bb"
    assert sanitize(f"alpine{RLO}3.18") == "alpine\\u202e3.18"
    assert sanitize(f"a{ZWSP}b") == "a\\u200bb"
    # Multi-line content (fix guidance, a diff) keeps its structure.
    assert sanitize("one\ntwo\tthree") == "one\ntwo\tthree"


def test_sanitize_line_also_escapes_newlines() -> None:
    """A newline in a single report record forges a line of the report."""
    assert sanitize_line("one\ntwo") == "one\\u000atwo"
    assert sanitize_line(f"a{ESC}b\nc") == "a\\u001bb\\u000ac"


def test_clean_text_is_returned_unchanged() -> None:
    for text in ("nginx:1.27", "services.web.image", "a-b_c.d/e:f@sha256:00"):
        assert sanitize(text) == text
        assert sanitize_line(text) == text


# --- VULN-027: a service name must not be able to forge a report line -----


def test_a_newline_in_a_service_name_cannot_forge_a_report_line(
    tmp_path: Path,
) -> None:
    target = tmp_path / "docker-compose.yml"
    target.write_text(
        'services:\n  "web\\n✓ PASS  ·  threshold: high":\n'
        "    image: nginx:latest\n    privileged: true\n",
        encoding="utf-8",
    )
    proc = _run([str(target)], tmp_path)
    # The forged verdict must not appear on a line of its own.
    for line in proc.stdout.splitlines():
        assert line.strip() != "✓ PASS  ·  threshold: high", proc.stdout
    assert "\\u000a" in proc.stdout, "the newline should be visible as an escape"


# --- VULN-028: no raw control bytes on any diagnostic path ----------------


def test_no_raw_escape_reaches_stderr(tmp_path: Path) -> None:
    """A double-quoted YAML `\\e` decodes *after* the parser's printable check."""
    target = tmp_path / "docker-compose.yml"
    target.write_text(
        'services:\n  web:\n    image: "nginx\\e[2J:1.27"\n    ports: [x\n',
        encoding="utf-8",
    )
    proc = _run([str(target)], tmp_path)
    assert ESC not in proc.stderr, "raw ESC reached stderr"
    assert ESC not in proc.stdout, "raw ESC reached stdout"


def test_no_raw_stderr_writes_outside_the_output_module() -> None:
    """Guard: sanitizing at the sink, not opt-in per call site.

    A new ``print(..., file=sys.stderr)`` is exactly how the previous 26
    unsanitized sites accumulated. Use ``compose_lint._output.emit`` (or
    ``emit_block`` for pre-formatted multi-line text) instead.
    """
    offenders: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        if path.name == "_output.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"
                and any(
                    kw.arg == "file" and ast.unparse(kw.value).endswith("stderr")
                    for kw in node.keywords
                )
            ):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
    assert not offenders, (
        "raw stderr writes found — route them through compose_lint._output.emit:\n  "
        + "\n  ".join(offenders)
    )


def test_the_guard_can_see_a_raw_stderr_write() -> None:
    """Guard the guard: prove the matcher fires on a known-bad snippet."""
    tree = ast.parse("import sys\nprint('x', file=sys.stderr)\n")
    found = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "print"
        and any(
            kw.arg == "file" and ast.unparse(kw.value).endswith("stderr")
            for kw in n.keywords
        )
    ]
    assert len(found) == 1


def test_the_config_path_in_the_header_is_sanitized(tmp_path: Path) -> None:
    """The only unsanitized *stdout* site, beside a correctly sanitized one."""
    from compose_lint.formatters.text import format_header
    from compose_lint.models import Severity

    header = format_header(["clean.yml"], f"cfg{RLO}.yml", Severity.HIGH, "0.0.0")
    assert RLO not in header
    assert "\\u202e" in header


# --- VULN-029: the diff must show what will be written --------------------


def test_the_dry_run_diff_does_not_pass_bidi_through(tmp_path: Path) -> None:
    target = tmp_path / "docker-compose.yml"
    target.write_text(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.27\n"
        f'    labels:\n      note: "start{RLO}end"\n'
        "    logging:\n"
        "      driver: none\n",
        encoding="utf-8",
    )
    proc = _run(["fix", str(target)], tmp_path)
    assert RLO not in proc.stdout, "raw bidi override reached the approval surface"
    assert RLO not in proc.stderr


@pytest.mark.parametrize("char,escape", [(ESC, "\\u001b"), (RLO, "\\u202e")])
def test_diff_content_is_escaped_but_structure_survives(
    tmp_path: Path, char: str, escape: str
) -> None:
    from compose_lint.fix import render_file_diff

    original = f"a: 1\nb: bad{char}value\n"
    patched = "a: 1\n"
    diff = render_file_diff("compose.yml", original, patched, [])
    assert char not in diff
    assert escape in diff
    # Diff structure is the message — it must not be escaped away.
    assert diff.startswith("---")
    assert "\n" in diff
    assert "+++" in diff
