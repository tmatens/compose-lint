"""Malformed input is a per-file failure, never a traceback.

The documented contract is exit 0 (clean), 1 (findings at or above the
threshold), 2 (compose-lint could not run). Four paths violated it by letting an
exception escape: the CLI printed a Python traceback, exited 1 — which reads as
"I linted it and it failed" — and abandoned every remaining file in the batch.

Each had a correct sibling in the same repo. The parser already translated
``RecursionError`` from the loader; the same hazard in the post-parse passes was
unguarded. The Compose loader was wrapped; the config loader was not.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

from compose_lint.config import ConfigError, load_config
from compose_lint.parser import ComposeError, loads
from tests._cli_env import cli_env

REPO_ROOT = Path(__file__).resolve().parent.parent

_FIXABLE = (
    "services:\n  web:\n    image: nginx:1.27\n    logging:\n      driver: none\n"
)
_PRIVILEGED = "services:\n  api:\n    image: nginx:latest\n    privileged: true\n"


def _deep_extends_chain(depth: int = 2000) -> str:
    body = ["services:"]
    for i in range(depth):
        body.append(f"  s{i}:")
        body.append("    image: nginx:1.27")
        body.append(f"    extends: {{service: s{i + 1}}}")
    body.append(f"  s{depth}:")
    body.append("    image: nginx:1.27")
    return "\n".join(body) + "\n"


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "compose_lint", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=cli_env(PYTHONPATH=str(REPO_ROOT / "src"), NO_COLOR="1"),
        timeout=180,
    )


def _assert_no_traceback(proc: subprocess.CompletedProcess[str]) -> None:
    assert "Traceback" not in proc.stderr, proc.stderr
    assert 'File "' not in proc.stderr, proc.stderr


@pytest.fixture
def restore_mode() -> Iterator[list[Path]]:
    touched: list[Path] = []
    yield touched
    for path in touched:
        with contextlib.suppress(OSError):
            path.chmod(0o755)


# --- VULN-005: the guard must cover every pass that walks the document ----


def test_a_deep_extends_chain_is_a_compose_error_not_a_crash() -> None:
    """`_resolve_in_file_extends` recurses; only the *parse* was guarded."""
    with pytest.raises(ComposeError, match="too deeply nested"):
        loads(_deep_extends_chain())


def test_a_deep_extends_chain_exits_two_with_no_traceback(tmp_path: Path) -> None:
    target = tmp_path / "docker-compose.yml"
    target.write_text(_deep_extends_chain(), encoding="utf-8")

    proc = _run([str(target)], tmp_path)
    assert proc.returncode == 2, proc.stderr
    _assert_no_traceback(proc)


def test_one_bad_file_does_not_abandon_the_batch(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yml"
    bad.write_text(_deep_extends_chain(), encoding="utf-8")
    good = tmp_path / "good.yml"
    good.write_text(_PRIVILEGED, encoding="utf-8")

    proc = _run(["--format", "json", str(bad), str(good)], tmp_path)
    assert proc.returncode == 2
    _assert_no_traceback(proc)
    # The clean file was still linted and its CRITICAL still reported.
    assert "CL-0002" in proc.stdout


# --- VULN-033: the loader constructor is inside the boundary --------------


def test_a_c0_byte_is_a_compose_error_not_a_reader_error() -> None:
    """`Reader.__init__` runs the printable check, so it raises at construction."""
    with pytest.raises(ComposeError, match="Invalid YAML"):
        loads("services:\n  web:\n    image: ngi\x00nx\n")


def test_a_c0_byte_exits_two_with_no_traceback(tmp_path: Path) -> None:
    target = tmp_path / "docker-compose.yml"
    target.write_bytes(b"services:\n  web:\n    image: ngi\x00nx\n")
    proc = _run([str(target)], tmp_path)
    assert proc.returncode == 2, proc.stderr
    _assert_no_traceback(proc)


# --- VULN-023: the config loader has the same hazard ---------------------


def test_a_deeply_nested_config_is_a_config_error(tmp_path: Path) -> None:
    config = tmp_path / ".compose-lint.yml"
    config.write_text("rules: " + "[" * 60_000 + "]" * 60_000, encoding="utf-8")
    with pytest.raises(ConfigError, match="too deeply nested"):
        load_config(config)


def test_a_deeply_nested_config_exits_two_with_no_traceback(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(_FIXABLE, encoding="utf-8")
    config = tmp_path / "deep.yml"
    config.write_text("rules: " + "[" * 60_000 + "]" * 60_000, encoding="utf-8")

    proc = _run(["--config", str(config), "docker-compose.yml"], tmp_path)
    assert proc.returncode == 2, proc.stderr
    _assert_no_traceback(proc)


# --- VULN-020: a write failure belongs to its file, not to the run -------


@pytest.mark.skipif(
    os.name != "posix",
    reason="chmod cannot make a directory unwritable on Windows",
)
def test_an_unwritable_directory_does_not_abort_the_batch(
    tmp_path: Path, restore_mode: list[Path]
) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    first = locked / "a.yml"
    first.write_text(_FIXABLE, encoding="utf-8")
    locked.chmod(0o555)
    restore_mode.append(locked)

    later = tmp_path / "later.yml"
    later.write_text(_FIXABLE, encoding="utf-8")

    proc = _run(
        ["fix", "--only", "CL-0014", "--apply", str(first), str(later)], tmp_path
    )

    assert proc.returncode == 2, proc.stderr
    _assert_no_traceback(proc)
    # The failure is attributed to the file it belongs to...
    assert "a.yml" in proc.stderr
    # ...and the later file was still examined and fixed.
    assert "driver: none" not in later.read_text(encoding="utf-8")


@pytest.mark.skipif(
    os.name != "posix",
    reason="chmod cannot make a directory unwritable on Windows",
)
def test_the_error_does_not_leak_the_internal_temp_filename(
    tmp_path: Path, restore_mode: list[Path]
) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    target = locked / "a.yml"
    target.write_text(_FIXABLE, encoding="utf-8")
    locked.chmod(0o555)
    restore_mode.append(locked)

    proc = _run(["fix", "--apply", str(target)], tmp_path)
    assert "Permission denied" in proc.stderr
    assert ".tmp" not in proc.stderr, proc.stderr
    assert "Errno" not in proc.stderr, proc.stderr


def test_init_to_a_directory_is_a_clean_error(tmp_path: Path) -> None:
    """A directory has st_nlink >= 2, so it must not be reported as a hard link."""
    (tmp_path / "docker-compose.yml").write_text(_PRIVILEGED, encoding="utf-8")
    out = tmp_path / "adirectory"
    out.mkdir()

    proc = _run(["init", "docker-compose.yml", "-o", str(out), "--force"], tmp_path)
    assert proc.returncode == 2, proc.stderr
    _assert_no_traceback(proc)
    assert "not a regular file" in proc.stderr
    assert "hard link" not in proc.stderr
    assert os.path.isdir(out)
