"""The Action must never be more permissive than the CLI it wraps.

Six defects shared that shape: a skipped step turned the CLI's fail-closed
"no Compose files" (exit 2) into a green check; `|| true` on the SARIF re-run
reported a destroyed artifact as success; the install ignored the pin a
SHA-pinned `uses:` implies; discovered paths crossed the step boundary through
a line-oriented file; and `sarif-file` was an unvalidated write target.

Every step's ``run:`` body is **extracted from action.yml here**, not copied,
so these tests cannot drift from the file they are asserting about. The runner
is emulated only where it has to be: ``env:`` blocks become real environment
variables under the same names, ``$GITHUB_OUTPUT`` becomes a real file parsed
the way the runner parses it, and ``pip``/``compose-lint`` are shimmed onto
PATH where the point is *what was invoked* rather than what it did.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
VENV_BIN = REPO_ROOT / ".venv" / "bin"

_INSECURE = (
    "services:\n"
    "  web:\n"
    "    image: nginx:latest\n"
    "    privileged: true\n"
    "    volumes:\n"
    "      - /var/run/docker.sock:/var/run/docker.sock\n"
)


def _action() -> dict[str, Any]:
    return yaml.safe_load((REPO_ROOT / "action.yml").read_text(encoding="utf-8"))


def _step(name: str) -> dict[str, Any]:
    for step in _action()["runs"]["steps"]:
        if step.get("name") == name:
            return step
    raise AssertionError(f"no step named {name!r}")


def _bash_major() -> int:
    try:
        out = subprocess.run(
            ["bash", "-c", "echo ${BASH_VERSINFO[0]}"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        return int(out)
    except (OSError, ValueError):
        return 0


_BASH_MAJOR = _bash_major()


def _run_step(
    name: str,
    env: dict[str, str],
    workspace: Path,
    outputs: Path,
    extra_path: Path | None = None,
) -> tuple[int, str, str]:
    """Execute a step's `run:` body the way the runner would."""
    if _BASH_MAJOR < 4:
        # The scripts target the GitHub runner's bash (5.x) and use
        # bash-4 features (`mapfile`). macOS ships bash 3.2, which fails
        # them for reasons the action never sees in production — every
        # `runs-on` that executes action.yml provides a modern bash. The
        # static assertions below still run everywhere.
        pytest.skip(
            "action.yml step scripts need bash >= 4 "
            f"(this platform has {_BASH_MAJOR or 'no bash'})"
        )
    script = _step(name)["run"]
    if extra_path is not None:
        _require_exec(extra_path)
    path = f"{VENV_BIN}:{os.environ.get('PATH', '')}"
    if extra_path is not None:
        path = f"{extra_path}:{path}"
    full_env = {
        "PATH": path,
        "HOME": str(workspace),
        "GITHUB_OUTPUT": str(outputs),
        "GITHUB_WORKSPACE": str(workspace),
        "RUNNER_TEMP": str(workspace / "_temp"),
        # Even a bypassed shim must never reach the network: a real pip
        # running here installs a published compose-lint over the editable
        # checkout under test (#595). With no index, that becomes a loud
        # local failure instead of silent environment corruption.
        "PIP_NO_INDEX": "1",
        **env,
    }
    (workspace / "_temp").mkdir(exist_ok=True)
    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
        cwd=workspace,
        env=full_env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _require_exec(shim_dir: Path) -> None:
    """Skip when ``shim_dir`` cannot execute files (a ``noexec`` tmpdir).

    PATH resolution silently passes over a non-executable entry, so on a
    host with ``/tmp`` mounted ``noexec`` the *real* tool runs instead of
    the shim. For the pip shim that meant a live network install replacing
    the editable checkout with a published compose-lint — corrupting every
    subsequent test run in a way that reads like source breakage (#595).
    Never fall through: probe an exec here and skip with the remedy.
    """
    probe = shim_dir / "exec-probe"
    probe.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    probe.chmod(0o755)
    try:
        subprocess.run([str(probe)], check=True, timeout=10)
    except OSError:
        pytest.skip(
            f"{shim_dir} cannot execute files (noexec tmpdir?) — set TMPDIR "
            "to an exec-capable directory, see CONTRIBUTING.md"
        )
    finally:
        probe.unlink()


def _outputs(path: Path) -> dict[str, str]:
    """Fold `key=value` records the way the runner does (last record wins)."""
    result: dict[str, str] = {}
    if not path.exists():
        return result
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            result[key] = value
    return result


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def outputs(tmp_path: Path) -> Path:
    p = tmp_path / "gh_output"
    p.write_text("", encoding="utf-8")
    return p


def _discover(ws: Path, outputs: Path, **env: str) -> tuple[int, str, str]:
    base = {"CL_FILES": "", "CL_PATTERN": ""}
    base.update(env)
    return _run_step("Find Compose files", base, ws, outputs)


def _lint(ws: Path, outputs: Path, **env: str) -> tuple[int, str, str]:
    base = {
        "CL_CONFIG": "",
        "CL_FAIL_ON": "high",
        "CL_SKIP_SUPPRESSED": "false",
        "CL_QUIET": "false",
        "CL_VERBOSE": "false",
        "CL_SARIF_FILE": "",
        "CL_ALLOW_NO_FILES": "false",
        "CL_COUNT": "0",
        "CL_LIST_FILE": "",
    }
    base.update(env)
    return _run_step("Run compose-lint", base, ws, outputs)


# --- VULN-037: "nothing to lint" is not a pass ----------------------------


def test_no_compose_files_fails_like_the_cli(ws: Path, outputs: Path) -> None:
    rc, _out, err = _lint(ws, outputs, CL_COUNT="0")
    assert rc == 2, "the CLI exits 2 with no Compose files; the Action must too"
    assert "No Compose files found" in err or "No Compose files found" in _out


def test_allow_no_files_opts_out(ws: Path, outputs: Path) -> None:
    rc, out, err = _lint(ws, outputs, CL_COUNT="0", CL_ALLOW_NO_FILES="true")
    assert rc == 0
    assert "::warning::" in (out + err)


def test_the_lint_step_is_not_gated_on_a_file_count(ws: Path, outputs: Path) -> None:
    """The skip is what turned exit 2 into a green check — it must not return.

    An `if:` on this step means the runner reports success without running
    anything, so the decision has to live inside the script where it can fail.
    """
    assert "if" not in _step("Run compose-lint"), (
        "the lint step must run unconditionally; a skipped step reports "
        "success without linting anything"
    )


# --- VULN-040: nothing attacker-controlled in $GITHUB_OUTPUT --------------


def test_a_newline_in_files_is_refused(ws: Path, outputs: Path) -> None:
    rc, out, err = _discover(ws, outputs, CL_FILES="a.yml\nfiles=evil")
    assert rc == 2, "a newline in a space-separated list is malformed"
    assert "newline" in (out + err)


def test_an_ordinary_files_input_is_accepted(ws: Path, outputs: Path) -> None:
    """The guard must reject only a newline, not every input.

    A pattern built with `$(printf '\\n')` collapses to the empty string and
    matches everything, which would refuse every `files:` value there is.
    """
    (ws / "a.yml").write_text(_INSECURE, encoding="utf-8")
    (ws / "b.yml").write_text(_INSECURE, encoding="utf-8")
    rc, out, err = _discover(ws, outputs, CL_FILES="a.yml b.yml")
    assert rc == 0, out + err
    recorded = _outputs(outputs)
    assert recorded["count"] == "2"
    entries = Path(recorded["list-file"]).read_bytes().split(b"\0")[:-1]
    assert entries == [b"a.yml", b"b.yml"], entries


def test_a_single_file_input_is_accepted(ws: Path, outputs: Path) -> None:
    (ws / "only.yml").write_text(_INSECURE, encoding="utf-8")
    rc, out, err = _discover(ws, outputs, CL_FILES="only.yml")
    assert rc == 0, out + err
    assert _outputs(outputs)["count"] == "1"


def test_discovery_puts_no_filename_into_github_output(ws: Path, outputs: Path) -> None:
    (ws / "docker-compose.yml").write_text(_INSECURE, encoding="utf-8")
    rc, _out, _err = _discover(ws, outputs)
    assert rc == 0
    recorded = _outputs(outputs)
    assert set(recorded) == {"count", "list-file"}, recorded
    assert recorded["count"] == "1"
    # The path travels in a file, not in the line-oriented output stream.
    assert "docker-compose.yml" not in outputs.read_text(encoding="utf-8")


def test_discovery_preserves_a_path_containing_spaces(ws: Path, outputs: Path) -> None:
    nested = ws / "my stack"
    nested.mkdir()
    (nested / "docker-compose.yml").write_text(_INSECURE, encoding="utf-8")
    rc, _out, _err = _discover(ws, outputs, CL_PATTERN="docker-compose.yml")
    assert rc == 0
    recorded = _outputs(outputs)
    assert recorded["count"] == "1"
    entries = Path(recorded["list-file"]).read_bytes().split(b"\0")[:-1]
    assert entries == [b"./my stack/docker-compose.yml"], entries


# --- VULN-038: never ship an artifact that was not written ----------------


def test_sarif_is_written_and_flagged_on_a_normal_run(ws: Path, outputs: Path) -> None:
    (ws / "docker-compose.yml").write_text(_INSECURE, encoding="utf-8")
    _discover(ws, outputs)
    listed = _outputs(outputs)["list-file"]
    sarif = ws / "results.sarif"

    rc, _out, _err = _lint(
        ws, outputs, CL_COUNT="1", CL_LIST_FILE=listed, CL_SARIF_FILE=str(sarif)
    )
    assert rc == 1, "findings present, so the gate fails"
    assert sarif.exists() and sarif.stat().st_size > 0
    json.loads(sarif.read_text(encoding="utf-8"))  # a complete document
    assert _outputs(outputs).get("sarif-written") == "true"


def test_a_failed_sarif_run_leaves_no_truncated_artifact(
    ws: Path, outputs: Path
) -> None:
    """The redirect used to truncate the target before the command ran.

    Combined with `|| true`, a failed run left a 0-byte file and reported
    success, and the upload shipped an empty result set as a clean scan.
    """
    (ws / "docker-compose.yml").write_text(_INSECURE, encoding="utf-8")
    _discover(ws, outputs)
    listed = _outputs(outputs)["list-file"]

    sarif = ws / "results.sarif"
    sarif.write_text("PREVIOUS CONTENT", encoding="utf-8")

    # A shim that fails the way a crashing linter would: no stdout, non-zero.
    shim_dir = ws / "shim"
    shim_dir.mkdir()
    shim = shim_dir / "compose-lint"
    shim.write_text(
        "#!/usr/bin/env bash\n"
        'for a in "$@"; do\n'
        '  if [ "$a" = "sarif" ]; then echo boom >&2; exit 2; fi\n'
        "done\n"
        f'exec {VENV_BIN / "compose-lint"} "$@"\n',
        encoding="utf-8",
    )
    shim.chmod(0o755)

    script_env = {
        "CL_CONFIG": "",
        "CL_FAIL_ON": "high",
        "CL_SKIP_SUPPRESSED": "false",
        "CL_QUIET": "false",
        "CL_VERBOSE": "false",
        "CL_SARIF_FILE": str(sarif),
        "CL_ALLOW_NO_FILES": "false",
        "CL_COUNT": "1",
        "CL_LIST_FILE": listed,
    }
    rc, out, err = _run_step(
        "Run compose-lint", script_env, ws, outputs, extra_path=shim_dir
    )

    assert rc != 0, "a SARIF run that produced nothing must not report success"
    assert "refusing to upload an empty artifact" in (out + err)
    # The previously valid artifact was not truncated by the redirect.
    assert sarif.read_text(encoding="utf-8") == "PREVIOUS CONTENT"
    assert _outputs(outputs).get("sarif-written") != "true"


def test_upload_is_gated_on_the_file_being_written(ws: Path) -> None:
    condition = str(_step("Upload SARIF")["if"])
    assert "sarif-written" in condition, condition
    assert "always()" not in condition, condition


def test_upload_can_be_switched_off(ws: Path) -> None:
    """`upload-sarif: false` must skip the Code Scanning upload.

    Runners without Code Scanning (Forgejo) and jobs without
    `security-events: write` — every fork PR — need the SARIF file without
    the upload; ci.yml's action-smoke relies on this to exercise
    `sarif-file` live.
    """
    action = _action()
    upload = action["inputs"]["upload-sarif"]
    assert upload["default"] == "true", "uploading must stay the default"
    condition = str(_step("Upload SARIF")["if"])
    assert "inputs.upload-sarif == 'true'" in condition, condition


def test_sarif_written_is_a_declared_output(ws: Path) -> None:
    """Callers assert on `sarif-written`; composite steps are private.

    A composite action exposes a step's outputs only through a declared
    `outputs:` mapping — dropping it would silently break every workflow
    gating on the output, including ci.yml's action-smoke.
    """
    value = _action()["outputs"]["sarif-written"]["value"]
    assert "steps.lint.outputs.sarif-written" in value, value


# --- VULN-041: the SARIF path is a write target ---------------------------


def test_sarif_file_outside_the_workspace_is_refused(
    ws: Path, outputs: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    (ws / "docker-compose.yml").write_text(_INSECURE, encoding="utf-8")
    _discover(ws, outputs)
    listed = _outputs(outputs)["list-file"]

    outside_dir = tmp_path_factory.mktemp("outside")
    victim = outside_dir / "important.txt"
    victim.write_text("do not truncate me", encoding="utf-8")

    rc, out, err = _lint(
        ws,
        outputs,
        CL_COUNT="1",
        CL_LIST_FILE=listed,
        CL_SARIF_FILE=str(victim),
    )
    assert rc == 2
    assert "inside the workspace" in (out + err)
    assert victim.read_text(encoding="utf-8") == "do not truncate me"


def test_sarif_traversal_out_of_the_workspace_is_refused(
    ws: Path, outputs: Path
) -> None:
    (ws / "docker-compose.yml").write_text(_INSECURE, encoding="utf-8")
    _discover(ws, outputs)
    listed = _outputs(outputs)["list-file"]
    rc, out, err = _lint(
        ws,
        outputs,
        CL_COUNT="1",
        CL_LIST_FILE=listed,
        CL_SARIF_FILE=str(ws / ".." / "escaped.sarif"),
    )
    assert rc == 2
    assert "inside the workspace" in (out + err)


# --- VULN-039: a SHA-pinned `uses:` should pin the package too ------------


def _pip_shim(ws: Path) -> tuple[Path, Path]:
    shim_dir = ws / "pipshim"
    shim_dir.mkdir()
    log = ws / "pip.log"
    shim = shim_dir / "pip"
    shim.write_text(
        f'#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> {log}\n', encoding="utf-8"
    )
    shim.chmod(0o755)
    return shim_dir, log


def test_install_pins_by_default(ws: Path, outputs: Path) -> None:
    shim_dir, log = _pip_shim(ws)
    rc, _out, _err = _run_step(
        "Install compose-lint", {"CL_VERSION": ""}, ws, outputs, extra_path=shim_dir
    )
    assert rc == 0
    assert "compose-lint==" in log.read_text(encoding="utf-8")


def test_install_tracks_pypi_only_when_asked(ws: Path, outputs: Path) -> None:
    shim_dir, log = _pip_shim(ws)
    rc, _out, _err = _run_step(
        "Install compose-lint",
        {"CL_VERSION": "latest"},
        ws,
        outputs,
        extra_path=shim_dir,
    )
    assert rc == 0
    assert log.read_text(encoding="utf-8").strip() == "install compose-lint"


def test_install_honours_an_explicit_version(ws: Path, outputs: Path) -> None:
    shim_dir, log = _pip_shim(ws)
    rc, _out, _err = _run_step(
        "Install compose-lint",
        {"CL_VERSION": "0.16.0"},
        ws,
        outputs,
        extra_path=shim_dir,
    )
    assert rc == 0
    assert "compose-lint==0.16.0" in log.read_text(encoding="utf-8")


def _failing_pip_shim(ws: Path, fail_times: int) -> tuple[Path, Path]:
    """A ``pip`` that fails its first ``fail_times`` calls, then succeeds.

    ``sleep`` is shimmed to a no-op alongside it so the retry loop's real
    backoff runs at full speed here. Shimming the clock rather than
    shortening it in ``action.yml`` keeps the published action's timing
    honest — the test exercises the loop consumers actually get.
    """
    shim_dir = ws / "pipshim"
    shim_dir.mkdir()
    log = ws / "pip.log"
    shim = shim_dir / "pip"
    shim.write_text(
        f"""#!/usr/bin/env bash
printf "%s\\n" "$*" >> {log}
attempts=$(wc -l < {log})
if [ "$attempts" -le {fail_times} ]; then
  echo "ERROR: No matching distribution found for compose-lint" >&2
  exit 1
fi
""",
        encoding="utf-8",
    )
    shim.chmod(0o755)
    noop_sleep = shim_dir / "sleep"
    noop_sleep.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    noop_sleep.chmod(0o755)
    return shim_dir, log


def test_install_retries_a_lagging_index(ws: Path, outputs: Path) -> None:
    """PyPI's /simple/ index lags a publish, so the first install can 404.

    The race broke this repo's own marketplace-smoke minutes after the
    0.20.0 publish (#612), and a consumer pinning a just-released version
    hits the identical window — which the action's pinned-by-default
    behaviour makes the normal case.
    """
    shim_dir, log = _failing_pip_shim(ws, fail_times=2)
    _require_exec(shim_dir)
    rc, _out, _err = _run_step(
        "Install compose-lint", {"CL_VERSION": ""}, ws, outputs, extra_path=shim_dir
    )
    assert rc == 0, "a lagging index must be retried, not fatal"
    attempts = log.read_text(encoding="utf-8").strip().splitlines()
    assert len(attempts) == 3, f"expected 2 failures then a success, got {attempts}"
    assert all("compose-lint==" in line for line in attempts)


def test_install_gives_up_naming_index_propagation(ws: Path, outputs: Path) -> None:
    """Retrying forever would just move the mystery; the message must land.

    A bare `Process completed with exit code 1` is what made the 0.20.0
    occurrence read as a regression instead of a propagation delay.
    """
    shim_dir, log = _failing_pip_shim(ws, fail_times=99)
    _require_exec(shim_dir)
    rc, out, err = _run_step(
        "Install compose-lint",
        {"CL_VERSION": "0.0.0"},
        ws,
        outputs,
        extra_path=shim_dir,
    )
    assert rc != 0
    assert len(log.read_text(encoding="utf-8").strip().splitlines()) == 6, (
        "the loop must be bounded"
    )
    assert "propagat" in (out + err), "the failure must name the index lag"


def test_the_default_pin_matches_the_package_version() -> None:
    """Drift here would ship an action that installs a different linter."""
    import re

    from compose_lint import __version__

    script = _step("Install compose-lint")["run"]
    match = re.search(r'DEFAULT_VERSION="([^"]+)"', script)
    assert match, "no DEFAULT_VERSION in the install step"
    assert match.group(1) == __version__, (
        f"action.yml pins {match.group(1)}, package is {__version__}"
    )
