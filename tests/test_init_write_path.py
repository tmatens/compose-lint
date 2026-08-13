"""`init` writes the file that governs which security rules are suppressed.

Two defects on that path. It could write a config that does not parse — and
report success doing it, so every later run in that directory failed at exit 2
until someone found the file by hand. And `--force` overwrote a read-only
policy, the one file where "do not modify" is a security decision, even though
`fix --apply` had honoured that mode all along.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from compose_lint.config import load_config
from compose_lint.config_emit import render_config
from compose_lint.models import Finding, Severity

REPO_ROOT = Path(__file__).resolve().parent.parent

_INSECURE = "services:\n  web:\n    image: nginx:latest\n    privileged: true\n"


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "compose_lint", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env={
            "PYTHONPATH": str(REPO_ROOT / "src"),
            "PATH": "/usr/bin:/bin",
            "NO_COLOR": "1",
        },
        timeout=120,
    )


@pytest.fixture
def restore_mode():
    touched: list[Path] = []
    yield touched
    for path in touched:
        with __import__("contextlib").suppress(OSError):
            path.chmod(0o644)


# --- VULN-030: what init writes must parse -------------------------------


@pytest.mark.parametrize(
    "service",
    [
        "web\n      other: x",  # a newline inside a mapping key
        "web\n",  # trailing newline — `$` matched before it
        'quote"name',
        "back\\slash",
        "colon: name",
        "tab\tname",
        "hash # name",
        "- dash",
        "\x85nel",
        "unicode-é",
    ],
)
def test_a_hostile_service_name_still_yields_a_parseable_config(
    tmp_path: Path, service: str
) -> None:
    findings = [
        Finding(
            rule_id="CL-0002",
            severity=Severity.CRITICAL,
            service=service,
            message="m",
            line=4,
        )
    ]
    config = tmp_path / ".compose-lint.yml"
    config.write_text(render_config(findings), encoding="utf-8")

    # The whole point: the file it wrote must load again.
    disabled, overrides, excluded = load_config(config)
    assert service in excluded["CL-0002"], excluded


def test_init_output_round_trips_end_to_end(tmp_path: Path) -> None:
    target = tmp_path / "docker-compose.yml"
    target.write_text(
        'services:\n  "web\\n      other: x":\n'
        "    image: nginx:latest\n    privileged: true\n",
        encoding="utf-8",
    )

    init = _run(["init", str(target)], tmp_path)
    assert init.returncode == 0, init.stderr

    # The next run in this directory must not fail on the config init wrote.
    check = _run([str(target)], tmp_path)
    assert "Invalid YAML in config file" not in check.stderr
    assert check.returncode != 2, check.stderr


def test_an_ordinary_service_name_is_still_emitted_unquoted() -> None:
    """The plain-scalar path is what keeps the generated file readable."""
    findings = [
        Finding(
            rule_id="CL-0002",
            severity=Severity.CRITICAL,
            service="web",
            message="m",
            line=4,
        )
    ]
    assert "      web: " in render_config(findings)


# --- VULN-036: a read-only policy file is a decision, not an obstacle ----


def test_init_force_refuses_a_read_only_config(
    tmp_path: Path, restore_mode: list[Path]
) -> None:
    target = tmp_path / "docker-compose.yml"
    target.write_text(_INSECURE, encoding="utf-8")
    config = tmp_path / ".compose-lint.yml"
    original = "rules: {}  # reviewed, do not modify\n"
    config.write_text(original, encoding="utf-8")
    config.chmod(0o444)
    restore_mode.append(config)

    proc = _run(["init", str(target), "--force"], tmp_path)

    assert proc.returncode == 2, proc.stderr
    assert "not writable" in proc.stderr
    assert config.read_text(encoding="utf-8") == original
    assert stat.S_IMODE(config.stat().st_mode) == 0o444


def test_init_still_writes_a_writable_config(tmp_path: Path) -> None:
    target = tmp_path / "docker-compose.yml"
    target.write_text(_INSECURE, encoding="utf-8")
    config = tmp_path / ".compose-lint.yml"
    config.write_text("rules: {}\n", encoding="utf-8")

    proc = _run(["init", str(target), "--force"], tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert "CL-0002" in config.read_text(encoding="utf-8")


def test_init_writes_a_fresh_config_when_none_exists(tmp_path: Path) -> None:
    """The guard must not block the ordinary first run."""
    target = tmp_path / "docker-compose.yml"
    target.write_text(_INSECURE, encoding="utf-8")

    proc = _run(["init", str(target)], tmp_path)
    assert proc.returncode == 0, proc.stderr
    written = tmp_path / ".compose-lint.yml"
    assert written.exists()
    assert os.access(written, os.W_OK)


def test_both_write_paths_share_one_guard() -> None:
    """`fix` had it and `init` did not; one definition keeps them together."""
    import ast

    source = (REPO_ROOT / "src" / "compose_lint" / "cli.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_refuses_write"
    ]
    assert len(calls) == 2, f"expected the fix and init paths, found {len(calls)}"
