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
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from compose_lint import cli
from compose_lint.config import load_config
from compose_lint.config_emit import render_config
from compose_lint.models import Finding, Severity
from tests._cli_env import cli_env

if TYPE_CHECKING:
    from collections.abc import Callable

REPO_ROOT = Path(__file__).resolve().parent.parent

_INSECURE = "services:\n  web:\n    image: nginx:latest\n    privileged: true\n"


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "compose_lint", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=cli_env(PYTHONPATH=str(REPO_ROOT / "src"), NO_COLOR="1"),
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


# --- init baselines the document check grades ----------------------------
#
# `check` merges the sibling override and reads the env files beside the
# Compose file (ADR-025/026/027); `init` read the raw file. A baseline written
# from the raw file therefore missed every finding the override or an
# `env_file:` contributed, and `check --config <baseline>` stayed red on the
# first stack that had one -- the opposite of what a baseline is for.

_HARDENED = (
    "services:\n  web:\n    image: i:1@sha256:" + "0" * 64 + "\n"
    "    read_only: true\n    cap_drop: [ALL]\n"
    "    security_opt: ['no-new-privileges:true']\n"
    "    mem_limit: 1g\n    cpus: 1\n    pids_limit: 100\n"
)
_OVERRIDE_PID_HOST = "services:\n  web:\n    pid: host\n"


def _write_stack(directory: Path, *, base: str = _HARDENED) -> Path:
    compose = directory / "compose.yml"
    compose.write_text(base, encoding="utf-8")
    (directory / "compose.override.yml").write_text(
        _OVERRIDE_PID_HOST, encoding="utf-8"
    )
    return compose


@dataclass
class _Result:
    returncode: int
    stdout: str
    stderr: str


@pytest.fixture
def run_cli_here(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Callable[[list[str], Path], _Result]:
    """Run the CLI in-process from ``cwd``, so coverage sees these paths.

    A subprocess run is invisible to the coverage gate, and every branch this
    class exists for -- the merge note, the COMPOSE_FILE reason, the env-file
    notes -- lives in init's planning code.
    """

    def run(args: list[str], cwd: Path) -> _Result:
        monkeypatch.chdir(cwd)
        monkeypatch.setenv("NO_COLOR", "1")
        capsys.readouterr()
        try:
            cli.main(args)
            code = 0
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
        out, err = capsys.readouterr()
        return _Result(code, out, err)

    return run


class TestInitGradesTheMergedStack:
    def test_baseline_makes_check_pass_when_the_override_adds_a_finding(
        self, tmp_path: Path, run_cli_here: Callable[[list[str], Path], _Result]
    ) -> None:
        compose = _write_stack(tmp_path)
        # The fixture is meaningful only if the override alone turns the gate
        # red: a hardened base, and `pid: host` (CL-0010, HIGH) merged on top.
        red = run_cli_here(["check", "-q", compose.name], tmp_path)
        assert red.returncode == 1, red.stderr
        assert "CL-0010" in red.stdout

        init = run_cli_here(["init", compose.name, "-o", "baseline.yml"], tmp_path)
        assert init.returncode == 0, init.stderr
        assert "merged compose.override.yml" in init.stderr

        check = run_cli_here(
            ["check", "--strict-config", "--config", "baseline.yml", compose.name],
            tmp_path,
        )
        assert check.returncode == 0, check.stdout + check.stderr

    def test_no_merge_overrides_baselines_the_base_alone(
        self, tmp_path: Path, run_cli_here: Callable[[list[str], Path], _Result]
    ) -> None:
        compose = _write_stack(tmp_path)

        proc = run_cli_here(
            ["init", "--no-merge-overrides", compose.name, "-o", "base.yml"], tmp_path
        )

        assert proc.returncode == 0, proc.stderr
        # The base is clean, so a baseline for the base alone has nothing in it
        # -- and init says so instead of writing an empty scaffold.
        assert "no findings" in proc.stderr
        assert not (tmp_path / "base.yml").exists()
        assert "merged" not in proc.stderr

    def test_summary_counts_the_override_findings(
        self, tmp_path: Path, run_cli_here: Callable[[list[str], Path], _Result]
    ) -> None:
        compose = _write_stack(tmp_path)

        proc = run_cli_here(["init", compose.name, "-o", "baseline.yml"], tmp_path)

        assert proc.returncode == 0, proc.stderr
        # Exactly the one finding the override contributes, counted once.
        summary = "wrote baseline.yml with 1 suppression(s) across 1 rule(s)"
        assert summary in proc.stderr
        _, _, excluded = load_config(tmp_path / "baseline.yml")
        assert excluded == {"CL-0010": {"web": "TODO: justify or fix"}}, excluded

    def test_env_file_credentials_are_baselined_like_check(
        self, tmp_path: Path, run_cli_here: Callable[[list[str], Path], _Result]
    ) -> None:
        compose = tmp_path / "compose.yml"
        compose.write_text(_HARDENED + "    env_file: secrets.env\n", encoding="utf-8")
        (tmp_path / "secrets.env").write_text(
            "POSTGRES_PASSWORD=hunter2\n", encoding="utf-8"
        )

        init = run_cli_here(["init", compose.name, "-o", "baseline.yml"], tmp_path)
        assert init.returncode == 0, init.stderr
        _, _, excluded = load_config(tmp_path / "baseline.yml")
        assert set(excluded) == {"CL-0020"}, excluded
        # The value itself never reaches the config or the status line.
        assert "hunter2" not in (tmp_path / "baseline.yml").read_text(encoding="utf-8")
        assert "hunter2" not in init.stderr

        check = run_cli_here(
            ["check", "--strict-config", "--config", "baseline.yml", compose.name],
            tmp_path,
        )
        assert check.returncode == 0, check.stdout + check.stderr

        # `--no-env` narrows init exactly as it narrows check: the env file is
        # unread, so there is no credential finding to baseline.
        blind = run_cli_here(
            ["init", "--no-env", compose.name, "-o", "blind.yml"], tmp_path
        )
        assert blind.returncode == 0, blind.stderr
        assert "no findings" in blind.stderr

    def test_compose_file_in_dotenv_selects_the_documents(
        self, tmp_path: Path, run_cli_here: Callable[[list[str], Path], _Result]
    ) -> None:
        # COMPOSE_FILE replaces discovery (ADR-026): the listed prod overlay is
        # merged and the sibling override is *not*, so the baseline must carry
        # the prod finding and nothing from the override.
        compose = _write_stack(tmp_path)
        (tmp_path / "compose.prod.yml").write_text(
            "services:\n  web:\n    privileged: true\n", encoding="utf-8"
        )
        (tmp_path / ".env").write_text(
            "COMPOSE_FILE=compose.yml:compose.prod.yml\n", encoding="utf-8"
        )

        proc = run_cli_here(["init", compose.name, "-o", "baseline.yml"], tmp_path)

        assert proc.returncode == 0, proc.stderr
        assert "COMPOSE_FILE in .env selects them" in proc.stderr
        _, _, excluded = load_config(tmp_path / "baseline.yml")
        assert "CL-0002" in excluded, excluded  # privileged, from compose.prod.yml
        assert "CL-0010" not in excluded, excluded  # pid: host, from the override
