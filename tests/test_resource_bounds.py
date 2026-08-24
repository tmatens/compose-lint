"""A small file must not be able to buy a large amount of work.

Every finding here shares a shape: input that parses in milliseconds and then
costs seconds or gigabytes downstream, while producing no finding and exiting 0
— so nothing in the output signals what happened. YAML aliases make a document
a DAG, and any pass that treats it as a tree pays 2^depth; a quadratic regex
turns a long scalar into CPU; and `.exists()` says yes to a FIFO.

Most assertions here are structural rather than timed, because a wall-clock
threshold is the flakiest thing you can put in CI. Where timing is the only
honest measure, the bound is generous — the defects were 4x-per-doubling, so a
loose ceiling still separates fixed from broken by orders of magnitude.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from compose_lint._limits import MAX_SUBSTITUTED_LEN
from compose_lint._lines import split_lines
from compose_lint._safe_read import MAX_FILE_BYTES, UnsafeFileError, read_text_bounded
from compose_lint._scalar import as_scalar_text
from compose_lint._yaml_edit import extends_targets, normalize_security_opt
from compose_lint.config import ConfigError, load_config
from compose_lint.engine import run_rules
from compose_lint.formatters.sarif import MAX_SARIF_RESULTS
from compose_lint.parser import ComposeError, loads
from compose_lint.rules._interpolation import _resolve_defaults
from tests._cli_env import cli_env

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run(args: list[str], cwd: Path, timeout: int = 120):
    return subprocess.run(
        [sys.executable, "-m", "compose_lint", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=cli_env(PYTHONPATH=str(REPO_ROOT / "src"), NO_COLOR="1"),
        timeout=timeout,
    )


def _alias_dag(depth: int, tail: str) -> str:
    """A doubling-by-reference alias chain: n nodes, 2^n leaves if expanded."""
    lines = ["x-l0: &l0 [a]"]
    for i in range(1, depth + 1):
        lines.append(f"x-l{i}: &l{i} [*l{i - 1}, *l{i - 1}]")
    return "\n".join(lines) + "\n" + tail


# --- Reading a path that is not a bounded regular file --------------------


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs require POSIX (os.mkfifo)")
def test_a_fifo_is_refused_instead_of_hanging(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    link = tmp_path / "docker-compose.yml"
    link.symlink_to(fifo)

    start = time.perf_counter()
    with pytest.raises(UnsafeFileError):
        read_text_bounded(link)
    # The point is that it returns at all; a plain open() blocks forever.
    assert time.perf_counter() - start < 10


@pytest.mark.skipif(os.name != "posix", reason="/dev/zero exists only on POSIX")
def test_a_character_device_is_refused_instead_of_allocating(tmp_path: Path) -> None:
    link = tmp_path / "docker-compose.yml"
    link.symlink_to(Path("/dev/zero"))
    with pytest.raises(UnsafeFileError):
        read_text_bounded(link)


def test_a_directory_is_refused(tmp_path: Path) -> None:
    # Refusal is the contract; the exception type differs by platform. POSIX
    # opens the directory and the S_ISREG check raises UnsafeFileError;
    # Windows already refuses at os.open with EACCES (PermissionError).
    with pytest.raises((UnsafeFileError, PermissionError)):
        read_text_bounded(tmp_path)


def test_a_symlink_to_a_real_file_is_still_followed(tmp_path: Path) -> None:
    """Only the resolved shape matters — a symlinked Compose file is ordinary."""
    real = tmp_path / "real.yml"
    real.write_text("services:\n  web:\n    image: nginx:1.27\n", encoding="utf-8")
    link = tmp_path / "docker-compose.yml"
    link.symlink_to(real)
    assert "nginx" in read_text_bounded(link)


def test_an_oversized_file_is_refused(tmp_path: Path) -> None:
    big = tmp_path / "big.yml"
    big.write_text("#" * (MAX_FILE_BYTES + 1), encoding="utf-8")
    with pytest.raises(UnsafeFileError, match="limit"):
        read_text_bounded(big)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs require POSIX (os.mkfifo)")
def test_the_cli_reports_a_fifo_and_keeps_going(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    poisoned = tmp_path / "poisoned.yml"
    poisoned.symlink_to(fifo)
    good = tmp_path / "good.yml"
    good.write_text(
        "services:\n  api:\n    image: nginx:latest\n    privileged: true\n",
        encoding="utf-8",
    )

    proc = _run(["--format", "json", str(poisoned), str(good)], tmp_path, timeout=60)
    assert proc.returncode == 2
    assert "Traceback" not in proc.stderr
    # The clean file was still linted.
    assert "CL-0002" in proc.stdout


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs require POSIX (os.mkfifo)")
def test_a_config_pointing_at_a_fifo_is_refused(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    cfg = tmp_path / "cfg.yml"
    cfg.symlink_to(fifo)
    with pytest.raises(ConfigError):
        load_config(cfg)


# --- `str()` on a container is an unbounded serialization ----------------


@pytest.mark.parametrize("value", [["a"], {"a": 1}, {"a"}, ("a",)])
def test_a_container_has_no_scalar_text(value: object) -> None:
    assert as_scalar_text(value) is None


@pytest.mark.parametrize(
    "value,expected", [("a", "a"), (1, "1"), (True, "True"), (None, "None")]
)
def test_a_scalar_keeps_its_text(value: object, expected: str) -> None:
    assert as_scalar_text(value) == expected


def test_an_alias_dag_under_cap_add_does_not_expand(tmp_path: Path) -> None:
    """22 levels is 4M leaves if serialized as a tree; the file is under 1 KB."""
    source = _alias_dag(
        22, "services:\n  web:\n    image: nginx:1.27\n    cap_add: *l22\n"
    )
    target = tmp_path / "docker-compose.yml"
    target.write_text(source, encoding="utf-8")
    assert len(source) < 2048

    start = time.perf_counter()
    proc = _run([str(target)], tmp_path, timeout=60)
    elapsed = time.perf_counter() - start
    assert proc.returncode in (0, 1), proc.stderr
    assert elapsed < 15, f"took {elapsed:.1f}s"


def test_an_alias_dag_in_a_config_reason_is_refused(tmp_path: Path) -> None:
    config = tmp_path / "cfg.yml"
    config.write_text(
        _alias_dag(22, "rules:\n  CL-0002:\n    enabled: false\n    reason: *l22\n"),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="must be a scalar"):
        load_config(config)


# --- Repeated work over one document -------------------------------------


def test_split_lines_is_memoized_per_document() -> None:
    """Each fixer asks for the same lines; re-splitting made collect_edits O(n^2)."""
    text = "services:\n  web:\n    image: nginx:1.27\n"
    assert split_lines(text) is split_lines(text)


def test_split_lines_still_answers_correctly_for_a_different_document() -> None:
    assert split_lines("a\nb\n") == ["a\n", "b\n"]
    assert split_lines("c\nd\n") == ["c\n", "d\n"]


def test_extends_targets_is_memoized_per_document() -> None:
    data, _lines = loads(
        "services:\n"
        "  base:\n    image: nginx:1.27\n"
        "  web:\n    extends:\n      service: base\n"
    )
    first = extends_targets(data)
    assert extends_targets(data) is first
    assert first == {"base"}


def test_a_deep_alias_dag_with_extends_resolves_quickly() -> None:
    """`_merge_extends` re-walked a shared subtree once per path: 805 B -> 5.4 s."""
    source = _alias_dag(
        18,
        "services:\n"
        "  base:\n    image: nginx:1.27\n    cap_add: *l18\n"
        "  web:\n    extends:\n      service: base\n",
    )
    start = time.perf_counter()
    loads(source)
    assert time.perf_counter() - start < 10


# --- Bounded regex scanning ----------------------------------------------


def test_a_long_connection_string_is_not_scanned_quadratically() -> None:
    from compose_lint.rules.CL0021_connection_string_credentials import (
        _find_inline_credential,
    )

    start = time.perf_counter()
    for size in (20_000, 40_000, 80_000):
        _find_inline_credential("a" * size + "@")
    assert time.perf_counter() - start < 5


def test_an_ordinary_connection_string_still_fires() -> None:
    data, lines = loads(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.27\n"
        "    environment:\n"
        "      DATABASE_URL: postgres://user:hunter2@db:5432/app\n"
    )
    ids = {f.rule_id for f in run_rules(data, lines)}
    assert "CL-0021" in ids


# --- Output that a consumer will actually accept --------------------------


def test_sarif_is_truncated_and_says_so(tmp_path: Path) -> None:
    lines = [
        "services:",
        "  base: &b",
        "    image: nginx:latest",
        "    privileged: true",
    ]
    for i in range(1500):
        lines += [f"  s{i}:", "    <<: *b"]
    target = tmp_path / "amp.yml"
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    proc = _run(["check", "--format", "sarif", str(target)], tmp_path, timeout=180)

    # GitHub Code Scanning rejects a document over 10 MB outright, so an
    # uncapped one produces no alerts at all.
    assert len(proc.stdout) < 10 * 1024 * 1024, f"{len(proc.stdout)} bytes"

    doc = json.loads(proc.stdout)
    run = doc["runs"][0]
    assert len(run["results"]) == MAX_SARIF_RESULTS
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert any(
        "omitted" in n["message"]["text"]
        for n in invocation["toolExecutionNotifications"]
    )
    # A gate must not read success from a knowingly incomplete artifact.
    assert proc.returncode == 2


def test_an_ordinary_run_is_not_truncated(tmp_path: Path) -> None:
    target = tmp_path / "docker-compose.yml"
    target.write_text(
        "services:\n  web:\n    image: nginx:latest\n    privileged: true\n",
        encoding="utf-8",
    )
    proc = _run(["check", "--format", "sarif", str(target)], tmp_path)
    doc = json.loads(proc.stdout)
    invocation = doc["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert "toolExecutionNotifications" not in invocation
    assert proc.returncode == 1


def test_a_malformed_document_is_still_a_compose_error() -> None:
    with pytest.raises(ComposeError):
        loads("services:\n  web:\n    image: [\n")


# --- Substitution is bounded on what it produces, not just what it scans ---
#
# `MAX_SCAN_LEN` bounds the *input* a pass will look at. It never fires here,
# because no single value is ever large: `${A}${A}` is four characters whose
# result is twice whatever `A` holds, so a ladder of definitions that each
# reference the one below doubles per rung. Thirty rungs is a 489-byte `.env`
# whose expansion is gigabytes.


def _doubling_env(rungs: int = 30) -> str:
    lines = ["K0=AAAA"]
    lines += [f"K{i}=${{K{i - 1}}}${{K{i - 1}}}" for i in range(1, rungs + 1)]
    return "\n".join(lines) + "\n"


def test_a_tiny_env_cannot_buy_an_unbounded_expansion(tmp_path: Path) -> None:
    """A 489-byte `.env` used to allocate until the runner died."""
    env = tmp_path / ".env"
    env.write_text(_doubling_env(), encoding="utf-8")
    assert len(env.read_bytes()) < 1024, "the point is that the input is tiny"
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  web:\n    image: nginx:1.27\n    environment:\n      X: ${K30}\n",
        encoding="utf-8",
    )

    start = time.monotonic()
    proc = _run(["check", "docker-compose.yml"], tmp_path, timeout=60)
    elapsed = time.monotonic() - start

    # The run completes and reports a verdict rather than dying mid-write.
    assert proc.returncode in (0, 1), proc.stderr
    assert "MemoryError" not in proc.stderr
    assert "Traceback" not in proc.stderr, proc.stderr
    assert elapsed < 30, f"took {elapsed:.1f}s; expansion is unbounded again"


def test_the_substitution_cap_returns_the_unknowable_answer() -> None:
    """Over the cap the value is not knowable, which is already `None`."""
    over = {"A": "x" * (MAX_SUBSTITUTED_LEN + 1)}
    assert _resolve_defaults("${A}", env=over) is None
    # Under it, resolution is unchanged.
    assert _resolve_defaults("${A:-ok}") == "ok"


# --- `str()` on an alias DAG, in the three predicates `_scalar` had missed ---


def _alias_ladder(field: str, rungs: int = 26) -> str:
    lines = ["services:", "  web:", "    image: nginx:1.27", "    x-l0: &l0 [a, b]"]
    lines += [f"    x-l{i}: &l{i} [*l{i - 1}, *l{i - 1}]" for i in range(1, rungs + 1)]
    lines.append(f"    {field}: *l{rungs}")
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize("field", ["security_opt", "pid", "ipc", "network_mode"])
def test_an_alias_dag_is_not_serialized_as_a_tree(tmp_path: Path, field: str) -> None:
    """`security_opt: [*l26]` is 690 bytes on disk and 2^26 via `str()`.

    `_caps.iter_cap_add` already refused this for `cap_add`; the CL-0003 /
    CL-0009 normalizer and CL-0010's namespace comparison did not.
    """
    target = tmp_path / "docker-compose.yml"
    target.write_text(_alias_ladder(field), encoding="utf-8")
    assert len(target.read_bytes()) < 2048, "the point is that the input is tiny"

    start = time.monotonic()
    proc = _run(["check", "docker-compose.yml"], tmp_path, timeout=60)
    elapsed = time.monotonic() - start

    assert proc.returncode in (0, 1), proc.stderr
    assert "Traceback" not in proc.stderr, proc.stderr
    assert elapsed < 20, f"took {elapsed:.1f}s; the DAG is being expanded again"


def test_a_non_scalar_security_opt_normalizes_to_nothing() -> None:
    """A list is not a directive Docker accepts, so it matches nothing."""
    assert normalize_security_opt(["seccomp:unconfined"]) == ""
    assert normalize_security_opt({"a": "b"}) == ""
    # Scalars are untouched.
    assert normalize_security_opt("seccomp=unconfined") == "seccomp:unconfined"
