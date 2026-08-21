"""End-to-end behaviour when Compose would merge an overlay into a base file.

`docker compose up` with no `-f` loads `compose.yml` *and* a sibling
`compose.override.yml`, merged, with no flag and no opt-in. These tests pin what
compose-lint does about that: it lints the merged configuration, says so, and
never lets `fix` write to a file whose findings it cannot attribute.

The merge itself is verified against the real Compose binary in
`test_merge_semantics.py`; this suite is about the CLI surface around it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

BASE_HARDENED = """\
services:
  web:
    image: myapp:1.0
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    read_only: true
    mem_limit: 512m
    cpus: 0.5
"""

OVERRIDE_DANGEROUS = """\
services:
  web:
    ports: ["8080:80"]
    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]
"""


def run_cli(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "compose_lint", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=cwd,
    )


def _write_pair(directory: Path, base: str, override: str) -> None:
    (directory / "compose.yml").write_text(base)
    (directory / "compose.override.yml").write_text(override)


def _findings(result: subprocess.CompletedProcess[str]) -> list[dict]:
    return json.loads(result.stdout)["findings"]


def test_socket_mount_in_the_overlay_is_reported(tmp_path: Path) -> None:
    """The finding that motivates all of this: a CRITICAL that used to be silent.

    Linting the base alone reports nothing about the mount, because the base
    does not contain it — but the stack that runs does.
    """
    _write_pair(tmp_path, BASE_HARDENED, OVERRIDE_DANGEROUS)
    result = run_cli("check", "--format", "json", "--fail-on", "low", cwd=tmp_path)

    rule_ids = {f["rule_id"] for f in _findings(result)}
    assert "CL-0001" in rule_ids


def test_overlay_absence_findings_are_not_false_positives(tmp_path: Path) -> None:
    """The overlay omits every hardening key; the base supplies them all.

    Linting the overlay standalone reports four absence findings that the merged
    configuration disproves. None of them may appear.
    """
    _write_pair(tmp_path, BASE_HARDENED, OVERRIDE_DANGEROUS)
    result = run_cli("check", "--format", "json", "--fail-on", "low", cwd=tmp_path)

    rule_ids = {f["rule_id"] for f in _findings(result)}
    # no-new-privileges, cap_drop, read_only and resource limits are all set by
    # the base and survive the merge.
    assert rule_ids.isdisjoint({"CL-0003", "CL-0006", "CL-0007", "CL-0026"})


def test_base_is_graded_against_the_configuration_that_runs(tmp_path: Path) -> None:
    """The asymmetry that is easy to miss: the *base* is mis-graded too.

    A base with no `read_only` reports CL-0007 on its own. When the overlay
    supplies `read_only: true`, the deployed container is read-only and the
    finding must disappear.
    """
    _write_pair(
        tmp_path,
        "services:\n  web:\n    image: myapp:1.0\n",
        "services:\n  web:\n    read_only: true\n",
    )
    result = run_cli("check", "--format", "json", "--fail-on", "low", cwd=tmp_path)

    assert "CL-0007" not in {f["rule_id"] for f in _findings(result)}


def test_merge_is_announced(tmp_path: Path) -> None:
    """Silence is the thing being fixed, so the merge must be visible."""
    _write_pair(tmp_path, BASE_HARDENED, OVERRIDE_DANGEROUS)
    result = run_cli("check", "--fail-on", "low", cwd=tmp_path)

    assert "compose.override.yml" in result.stderr
    assert "merged" in result.stderr


def test_merge_warning_does_not_change_the_exit_code(tmp_path: Path) -> None:
    """Merging is coverage achieved, not a coverage gap — never exit 2.

    An unresolved `include:` exits 2 because part of the stack was not linted.
    Here the opposite happened: more of the stack was linted than before. Exit
    stays finding-driven so a pinned CI pipeline is not broken by the upgrade.
    """
    _write_pair(
        tmp_path,
        "services:\n  web:\n    image: myapp:1.0@sha256:" + "0" * 64 + "\n",
        "services:\n  web:\n    read_only: true\n",
    )
    result = run_cli("check", "--fail-on", "critical", cwd=tmp_path)

    assert result.returncode == 0, result.stderr


def test_findings_name_the_file_they_came_from(tmp_path: Path) -> None:
    """A finding whose evidence is in the overlay must say so.

    Without this the report shows a line number from one file against the name
    of another, which is worse than not reporting the file at all.
    """
    _write_pair(tmp_path, BASE_HARDENED, OVERRIDE_DANGEROUS)
    result = run_cli("check", "--format", "json", "--fail-on", "low", cwd=tmp_path)

    socket = next(f for f in _findings(result) if f["rule_id"] == "CL-0001")
    assert socket["source_file"].endswith("compose.override.yml")
    # Line 4 of the *override*, which is where the mount is written.
    assert socket["line"] == 4


def test_text_excerpt_is_read_from_the_contributing_file(tmp_path: Path) -> None:
    """The rendered source excerpt must quote the line the finding is about."""
    _write_pair(tmp_path, BASE_HARDENED, OVERRIDE_DANGEROUS)
    result = run_cli("check", "--fail-on", "low", cwd=tmp_path)

    assert "/var/run/docker.sock:/var/run/docker.sock" in result.stdout
    # The base's line 4 is `security_opt:` — quoting it here would be the bug.
    assert "security_opt: [no-new-privileges:true]" not in result.stdout


def test_explicitly_listed_overlay_is_not_linted_standalone(tmp_path: Path) -> None:
    """`compose-lint *.yml` expands to the overlay; it must still be merged.

    A shell glob is the common way to lint several files, and it is how the
    standalone false positives reach a user who never typed the overlay's name.
    """
    _write_pair(tmp_path, BASE_HARDENED, OVERRIDE_DANGEROUS)
    result = run_cli(
        "check",
        "compose.yml",
        "compose.override.yml",
        "--format",
        "json",
        "--fail-on",
        "low",
        cwd=tmp_path,
    )

    findings = _findings(result)
    rule_ids = {f["rule_id"] for f in findings}
    assert rule_ids.isdisjoint({"CL-0003", "CL-0006", "CL-0007", "CL-0026"})
    # And the socket is reported exactly once, not once per listed file.
    assert sum(1 for f in findings if f["rule_id"] == "CL-0001") == 1


def test_fix_refuses_to_write_when_an_overlay_is_merged(tmp_path: Path) -> None:
    """`fix` edits one file; a merged run's findings may belong to the other.

    Adding `read_only: true` to the base is a wrong edit when the overlay turns
    it off again, so refusing is the only answer that cannot corrupt intent.
    """
    _write_pair(
        tmp_path,
        "services:\n  web:\n    image: myapp:1.0\n",
        "services:\n  web:\n    ports: ['8080:80']\n",
    )
    before = (tmp_path / "compose.yml").read_text()
    result = run_cli("fix", "--apply", cwd=tmp_path)

    assert (tmp_path / "compose.yml").read_text() == before
    assert "skipped" in result.stderr
    assert "compose.override.yml" in result.stderr


def test_no_overlay_means_no_behaviour_change(tmp_path: Path) -> None:
    """The overwhelmingly common case must be byte-for-byte what it was."""
    (tmp_path / "compose.yml").write_text(BASE_HARDENED)
    result = run_cli("check", "--fail-on", "low", cwd=tmp_path)

    assert "merged" not in result.stderr
    assert "(merged into this run)" not in result.stdout
