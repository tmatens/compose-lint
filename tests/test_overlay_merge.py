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
import shutil
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


# `docker compose config` is the only external dependency in this suite, and it
# is not on the macOS/Windows smoke runners. A decorator rather than an inline
# check because the inline form ran *after* the subprocess call in one test, so
# the guard never fired and the runner raised FileNotFoundError instead of
# skipping — invisible locally, where docker is installed.
requires_docker = pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="needs the docker compose CLI",
)

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


def test_fix_edits_findings_written_in_the_file_it_is_fixing(tmp_path: Path) -> None:
    """`fix` writes the base's own findings and defers the overlay's.

    A finding whose line belongs to this file can be edited here: the line is a
    line in this text and the fix lands where the user would put it by hand. An
    absence finding is safe for the same reason — it only fires when the key is
    missing from the *merged* document, so adding it to the base really does
    harden what Compose runs.
    """
    _write_pair(
        tmp_path,
        'services:\n  web:\n    image: myapp:1.0\n    ports:\n      - "8080:80"\n',
        "services:\n  web:\n    volumes:\n"
        '      - "/var/run/docker.sock:/var/run/docker.sock"\n',
    )
    overlay_before = (tmp_path / "compose.override.yml").read_text()
    result = run_cli("fix", "--apply", cwd=tmp_path)

    base_after = (tmp_path / "compose.yml").read_text()
    # The base's own port finding is fixed in place...
    assert "127.0.0.1:8080:80" in base_after
    # ...and the overlay is never a write target.
    assert (tmp_path / "compose.override.yml").read_text() == overlay_before
    assert "need manual review" in result.stderr


@requires_docker
def test_fix_leaves_a_document_compose_still_accepts(tmp_path: Path) -> None:
    """The patched pair must remain a valid project, not just valid YAML."""
    _write_pair(
        tmp_path,
        'services:\n  web:\n    image: myapp:1.0\n    ports:\n      - "8080:80"\n',
        'services:\n  web:\n    volumes:\n      - "/app:/app"\n',
    )
    run_cli("fix", "--apply", cwd=tmp_path)

    check = subprocess.run(
        ["docker", "compose", "config"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stderr


def test_no_merge_overrides_restores_single_file_grading(tmp_path: Path) -> None:
    """The opt-out has to reproduce the pre-merge result exactly.

    Someone publishing the base as a template, with the overlay local-only, may
    legitimately want it graded alone — and the flag is the escape hatch if the
    merge is ever wrong.
    """
    _write_pair(tmp_path, BASE_HARDENED, OVERRIDE_DANGEROUS)
    result = run_cli(
        "check",
        "--no-merge-overrides",
        "--format",
        "json",
        "--fail-on",
        "low",
        cwd=tmp_path,
    )

    rule_ids = {f["rule_id"] for f in _findings(result)}
    # The overlay is not read, so its socket mount is not seen — the old
    # behaviour, now reachable only by asking for it.
    assert "CL-0001" not in rule_ids
    assert "merged" not in result.stderr


def test_banner_names_both_documents(tmp_path: Path) -> None:
    """The header states what was read, so it must state both files.

    Naming only the base is the complaint this behaviour answers; leaving the
    banner alone would move the false claim rather than remove it.
    """
    _write_pair(tmp_path, BASE_HARDENED, OVERRIDE_DANGEROUS)
    result = run_cli("check", "--fail-on", "low", cwd=tmp_path)

    assert "files: compose.yml + compose.override.yml" in result.stdout


def test_no_overlay_means_no_behaviour_change(tmp_path: Path) -> None:
    """The overwhelmingly common case must be byte-for-byte what it was."""
    (tmp_path / "compose.yml").write_text(BASE_HARDENED)
    result = run_cli("check", "--fail-on", "low", cwd=tmp_path)

    assert "merged" not in result.stderr
    assert "(merged into this run)" not in result.stdout


def test_sarif_points_at_the_contributing_file(tmp_path: Path) -> None:
    """Code Scanning annotates the artifact SARIF names, so it must be right.

    A finding whose line belongs to the overlay, reported against the base
    file's URI, annotates an unrelated line of an unrelated file.
    """
    _write_pair(tmp_path, BASE_HARDENED, OVERRIDE_DANGEROUS)
    result = run_cli("check", "--format", "sarif", "--fail-on", "low", cwd=tmp_path)
    results = json.loads(result.stdout)["runs"][0]["results"]

    by_rule = {r["ruleId"]: r["locations"][0]["physicalLocation"] for r in results}
    socket = by_rule["CL-0001"]
    assert socket["artifactLocation"]["uri"].endswith("compose.override.yml")
    assert socket["region"]["startLine"] == 4
    # A finding whose evidence is in the base keeps the base's URI, so its
    # partialFingerprints are unchanged (ADR-024).
    assert by_rule["CL-0019"]["artifactLocation"]["uri"].endswith("compose.yml")


def test_sarif_offers_no_suggested_fix_on_a_merged_run(tmp_path: Path) -> None:
    """`fix` refuses a merged run; SARIF must not offer the same edit anyway."""
    _write_pair(tmp_path, BASE_HARDENED, OVERRIDE_DANGEROUS)
    result = run_cli("check", "--format", "sarif", "--fail-on", "low", cwd=tmp_path)
    results = json.loads(result.stdout)["runs"][0]["results"]

    assert all(not r.get("fixes") for r in results)


ALL_FIXERS_BASE = """\
services:
  web:
    image: myapp:1.0
    ports:
      - "8080:80"
    security_opt:
      - seccomp:unconfined
    logging:
      driver: "none"
"""


# Contributes an unfixable finding without touching any key the base declares,
# so every base-side finding keeps base provenance. Using OVERRIDE_DANGEROUS
# here instead was a fixture bug worth remembering: it republishes the same
# "8080:80", which under keyed merge means the overlay's entry wins and the
# CL-0005 finding is correctly deferred rather than fixed.
OVERRIDE_SOCKET_ONLY = """\
services:
  web:
    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]
"""


def test_every_fixer_runs_on_a_merged_document(tmp_path: Path) -> None:
    """All five fixers, on a base whose overlay contributes an unfixable finding.

    Each fixer reads the *merged* data and edits the base's text, so any of them
    could splice at a line belonging to the other document. Exercising one of
    the five and generalising was how the earlier version of this change passed
    while `verify_apply` was still comparing a merged run against a single-file
    re-lint.
    """
    _write_pair(tmp_path, ALL_FIXERS_BASE, OVERRIDE_SOCKET_ONLY)
    result = run_cli("fix", "--apply", cwd=tmp_path)
    after = (tmp_path / "compose.yml").read_text()

    # CL-0005 rebinds the port, CL-0003 adds no-new-privileges, CL-0007 adds
    # read_only, CL-0009 drops the unconfined profile, CL-0014 drops the
    # disabled logging driver.
    assert "127.0.0.1:8080:80" in after
    assert "no-new-privileges:true" in after
    assert "read_only: true" in after
    assert "seccomp:unconfined" not in after
    assert 'driver: "none"' not in after
    # The overlay's socket mount is not fixable and must be reported, not edited.
    assert "need manual review" in result.stderr


@requires_docker
def test_fixed_merged_pair_is_still_a_valid_project(tmp_path: Path) -> None:
    """Compose must accept the pair after every fixer has written to the base."""
    _write_pair(tmp_path, ALL_FIXERS_BASE, OVERRIDE_SOCKET_ONLY)
    run_cli("fix", "--apply", cwd=tmp_path)

    check = subprocess.run(
        ["docker", "compose", "config"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stderr


def test_overlay_provenance_findings_are_never_fixed(tmp_path: Path) -> None:
    """The same rule, written in the overlay, must be left alone.

    CL-0009 has a fixer, so the deferral cannot be explained by the rule being
    unfixable — only by where the finding is written.
    """
    _write_pair(
        tmp_path,
        "services:\n  web:\n    image: myapp:1.0\n",
        "services:\n  web:\n    security_opt:\n      - seccomp:unconfined\n",
    )
    overlay_before = (tmp_path / "compose.override.yml").read_text()
    result = run_cli("fix", "--apply", cwd=tmp_path)

    assert (tmp_path / "compose.override.yml").read_text() == overlay_before
    assert "seccomp:unconfined" not in (tmp_path / "compose.yml").read_text()
    assert "need manual review" in result.stderr


def test_merged_fix_preserves_crlf_line_endings(tmp_path: Path) -> None:
    """`fix` writes to user files, and a merged run is a new path into that.

    `fix` reads with `newline=""` so a CRLF file is rewritten with CRLF; the
    merged path adds a second document to the read, and getting it wrong
    rewrites every line's ending while the diff shows one.
    """
    base = (
        "services:\r\n  web:\r\n    image: myapp:1.0\r\n"
        '    ports:\r\n      - "8080:80"\r\n'
    )
    (tmp_path / "compose.yml").write_bytes(base.encode())
    (tmp_path / "compose.override.yml").write_bytes(
        b'services:\r\n  web:\r\n    volumes:\r\n      - "/app:/app"\r\n'
    )

    run_cli("fix", "--apply", cwd=tmp_path)
    after = (tmp_path / "compose.yml").read_bytes()

    assert b"127.0.0.1:8080:80" in after, "the fix did not apply"
    assert b"\r\n" in after, "CRLF endings were lost"
    # No line may have been converted to bare LF.
    assert after.replace(b"\r\n", b"").count(b"\n") == 0, (
        "mixed endings: some lines were rewritten as LF"
    )


def test_merged_fix_leaves_lf_files_alone(tmp_path: Path) -> None:
    """The converse: an LF file must not acquire CRLF from the merged path."""
    _write_pair(
        tmp_path,
        'services:\n  web:\n    image: myapp:1.0\n    ports:\n      - "8080:80"\n',
        'services:\n  web:\n    volumes:\n      - "/app:/app"\n',
    )
    run_cli("fix", "--apply", cwd=tmp_path)
    after = (tmp_path / "compose.yml").read_bytes()

    assert b"127.0.0.1:8080:80" in after
    assert b"\r\n" not in after


def test_a_key_the_overlay_republishes_belongs_to_the_overlay(tmp_path: Path) -> None:
    """Identical values still move provenance: the overlay's entry is the one that wins.

    The base and overlay both publish `8080:80`. Under keyed merge the overlay's
    entry replaces the base's, so the CL-0005 finding is written in the overlay
    and `fix` must defer it rather than editing the base's now-superseded line.
    """
    _write_pair(
        tmp_path,
        'services:\n  web:\n    image: myapp:1.0\n    ports:\n      - "8080:80"\n',
        'services:\n  web:\n    ports: ["8080:80"]\n',
    )
    result = run_cli("fix", "--apply", cwd=tmp_path)

    assert '- "8080:80"' in (tmp_path / "compose.yml").read_text()
    assert "127.0.0.1" not in (tmp_path / "compose.yml").read_text()
    assert "need manual review" in result.stderr
