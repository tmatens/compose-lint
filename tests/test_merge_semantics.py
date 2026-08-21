"""Differential test: does our merge agree with Docker Compose itself?

The merge table in ``compose_lint._merge`` was derived by probing
``docker compose config``. Comments rot; this suite re-derives the same
behaviour from the real binary on every run, so a Compose release that changes
a merge rule fails here rather than silently mis-grading a user's stack.

The comparison is on **findings**, not on document shape. ``docker compose
config`` normalises what it emits (short volume syntax to long, list
``environment`` to a mapping, ports to structured entries) and our merge
deliberately does not, because rules read the spelling the user typed. Linting
both and comparing the finding sets asks the question that actually matters:
would a user be told the same thing either way?

Skipped when the ``docker compose`` CLI is unavailable, so the suite still runs
in environments without it.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest

from compose_lint.engine import run_rules
from compose_lint.parser import load_compose, load_merged

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="differential merge test needs the docker compose CLI",
)


def _compose_config(directory: Path) -> str:
    """Ground truth: the effective configuration Compose itself resolves."""
    result = subprocess.run(
        ["docker", "compose", "config"],
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        pytest.skip(f"compose rejected the fixture: {result.stderr.strip()[:200]}")
    return result.stdout


def _findings_of(data: dict, lines: dict[str, int]) -> set[tuple[str, str, str | None]]:
    return {
        (f.rule_id, f.service, f.evidence)
        for f in run_rules(data, lines)
        if not f.suppressed
    }


def _write_pair(directory: Path, base: str, override: str) -> None:
    (directory / "compose.yml").write_text(base)
    (directory / "compose.override.yml").write_text(override)


BASE_HARDENED = """\
services:
  web:
    image: myapp:1.0
    security_opt: [no-new-privileges:true]
    cap_drop: [ALL]
    read_only: true
    mem_limit: 512m
    cpus: 0.5
    user: "1000:1000"
"""

# (id, base, override) — each exercises one merge strategy that a naive
# recursive merge gets wrong.
CASES = [
    (
        "override-adds-socket-and-port",
        BASE_HARDENED,
        """\
services:
  web:
    ports: ["8080:80"]
    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]
""",
    ),
    (
        "override-replaces-mount-at-same-target",
        """\
services:
  web:
    image: myapp:1.0
    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]
""",
        """\
services:
  web:
    volumes: ["/tmp/harmless:/var/run/docker.sock"]
""",
    ),
    (
        "override-adds-mount-at-new-target",
        """\
services:
  web:
    image: myapp:1.0
    volumes: ["/app:/app"]
""",
        """\
services:
  web:
    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]
""",
    ),
    (
        "override-relaxes-hardening",
        BASE_HARDENED,
        """\
services:
  web:
    read_only: false
    privileged: true
""",
    ),
    (
        "cap-add-dedup-and-append",
        """\
services:
  web:
    image: myapp:1.0
    cap_drop: [ALL]
    cap_add: [SYS_ADMIN]
""",
        """\
services:
  web:
    cap_add: [SYS_ADMIN, NET_ADMIN]
""",
    ),
    (
        "device-replaced-at-same-target",
        """\
services:
  web:
    image: myapp:1.0
    devices: ["/dev/mem:/dev/probe"]
""",
        """\
services:
  web:
    devices: ["/dev/null:/dev/probe"]
""",
    ),
    (
        "security-opt-appends",
        """\
services:
  web:
    image: myapp:1.0
    security_opt: ["no-new-privileges:true"]
""",
        """\
services:
  web:
    security_opt: ["seccomp:unconfined"]
""",
    ),
    (
        "ports-same-target-different-host-port",
        """\
services:
  web:
    image: myapp:1.0
    ports: ["127.0.0.1:8080:80"]
""",
        """\
services:
  web:
    ports: ["9999:80"]
""",
    ),
    (
        "service-only-in-override",
        """\
services:
  web:
    image: myapp:1.0
""",
        """\
services:
  extra:
    image: other:1.0
    privileged: true
""",
    ),
    (
        "environment-map-plus-list",
        """\
services:
  web:
    image: myapp:1.0
    environment: {AWS_SECRET_ACCESS_KEY: "AKIAIOSFODNN7EXAMPLE"}
""",
        """\
services:
  web:
    environment: ["OTHER=1"]
""",
    ),
    (
        "reset-removes-inherited-hardening",
        BASE_HARDENED,
        """\
services:
  web:
    read_only: !reset null
    cap_drop: !reset null
""",
    ),
    (
        "reset-removes-inherited-socket",
        """\
services:
  web:
    image: myapp:1.0
    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]
""",
        """\
services:
  web:
    volumes: !reset null
""",
    ),
    (
        "logging-driver-swap-drops-options",
        """\
services:
  web:
    image: myapp:1.0
    logging: {driver: "json-file", options: {max-size: "1m"}}
""",
        """\
services:
  web:
    logging: {driver: "none"}
""",
    ),
]


@pytest.mark.parametrize("case_id,base,override", CASES, ids=[c[0] for c in CASES])
def test_merge_matches_docker_compose(
    case_id: str, base: str, override: str, tmp_path: Path
) -> None:
    """Our merged document yields the findings Compose's own merge would."""
    _write_pair(tmp_path, base, override)

    # Ground truth: lint the configuration Compose says it will run.
    truth_file = tmp_path / "truth.yml"
    truth_file.write_text(_compose_config(tmp_path))
    truth_data, truth_lines = load_compose(truth_file)
    expected = _findings_of(truth_data, truth_lines)

    merged = load_merged([tmp_path / "compose.yml", tmp_path / "compose.override.yml"])
    actual = _findings_of(merged.data, merged.lines)

    assert actual == expected, (
        f"{case_id}: merge disagrees with docker compose\n"
        f"  only ours:   {sorted(actual - expected)}\n"
        f"  only theirs: {sorted(expected - actual)}"
    )


def test_provenance_points_at_the_contributing_file(tmp_path: Path) -> None:
    """A finding's evidence must be attributable to the file that wrote it."""
    _write_pair(
        tmp_path,
        BASE_HARDENED,
        "services:\n  web:\n"
        '    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]\n',
    )
    merged = load_merged([tmp_path / "compose.yml", tmp_path / "compose.override.yml"])

    # The socket mount came from the override...
    assert merged.sources["services.web.volumes[0]"].endswith("compose.override.yml")
    assert merged.lines["services.web.volumes[0]"] == 3
    # ...while untouched hardening still points at the base file.
    assert merged.sources["services.web.read_only"].endswith("compose.yml")
    assert merged.lines["services.web.read_only"] == 6


def test_merge_is_order_sensitive(tmp_path: Path) -> None:
    """Swapping the documents swaps which value wins — merge is not a union."""
    _write_pair(
        tmp_path,
        "services:\n  web:\n    image: a:1\n    read_only: true\n",
        "services:\n  web:\n    read_only: false\n",
    )
    forward = load_merged([tmp_path / "compose.yml", tmp_path / "compose.override.yml"])
    backward = load_merged(
        [tmp_path / "compose.override.yml", tmp_path / "compose.yml"]
    )
    assert forward.data["services"]["web"]["read_only"] is False
    assert backward.data["services"]["web"]["read_only"] is True


# Fields Compose emits as plain string lists, unnormalised, so our merged value
# can be compared to its output directly. Findings-level comparison is blind to
# these: a rule reads `cap_add` as a set, so a duplicated entry changes nothing
# it reports. Shape comparison is the only thing that pins append-order and
# deduplication.
VERBATIM_LIST_FIELDS = ["cap_add", "cap_drop", "dns", "expose", "tmpfs"]


@pytest.mark.parametrize("field_name", VERBATIM_LIST_FIELDS)
def test_append_fields_match_compose_shape(field_name: str, tmp_path: Path) -> None:
    """Append-style sequences keep Compose's order and its deduplication."""
    values = {
        "cap_add": (["SYS_ADMIN", "NET_ADMIN"], ["NET_ADMIN", "SYS_PTRACE"]),
        "cap_drop": (["ALL"], ["ALL", "NET_RAW"]),
        "dns": (["1.1.1.1"], ["1.1.1.1", "8.8.8.8"]),
        "expose": (['"80"'], ['"80"', '"90"']),
        "tmpfs": (["/tmp"], ["/tmp", "/run"]),
    }[field_name]
    base_list = "[" + ", ".join(values[0]) + "]"
    over_list = "[" + ", ".join(values[1]) + "]"
    _write_pair(
        tmp_path,
        f"services:\n  web:\n    image: myapp:1.0\n    {field_name}: {base_list}\n",
        f"services:\n  web:\n    {field_name}: {over_list}\n",
    )

    truth_file = tmp_path / "truth.yml"
    truth_file.write_text(_compose_config(tmp_path))
    truth_data, _ = load_compose(truth_file)
    expected = truth_data["services"]["web"].get(field_name)

    merged = load_merged([tmp_path / "compose.yml", tmp_path / "compose.override.yml"])
    actual = merged.data["services"]["web"].get(field_name)

    # Compose stringifies numeric-looking entries; compare as strings.
    assert [str(v) for v in actual] == [str(v) for v in expected]


# Every field whose merge strategy differs, crossed with every Compose merge
# directive. Hand-picked cases test what the author thought of: `!override` was
# probed while deriving the table above, was not turned into a case, and the
# merge shipped ignoring it — an overlay dropping `no-new-privileges` via
# `security_opt: !override [...]` left the base's entry visible, so the absence
# rule stayed silent on hardening Compose had removed. The matrix below is
# mechanical precisely so it does not depend on remembering.
DIRECTIVE_FIELDS = [
    # (field, base value, override value) — the override is the interesting half
    (
        "volumes",
        '["/var/run/docker.sock:/var/run/docker.sock"]',
        '["/tmp/safe:/var/run/docker.sock"]',
    ),
    ("volumes", '["/app:/app"]', '["/var/run/docker.sock:/var/run/docker.sock"]'),
    ("devices", '["/dev/mem:/dev/probe"]', '["/dev/null:/dev/probe"]'),
    ("ports", '["127.0.0.1:8080:80"]', '["9999:80"]'),
    ("cap_add", "[SYS_ADMIN]", "[NET_ADMIN]"),
    ("cap_drop", "[ALL]", "[NET_RAW]"),
    ("security_opt", '["no-new-privileges:true"]', '["seccomp:unconfined"]'),
    ("tmpfs", '["/tmp"]', '["/run:exec"]'),
    ("environment", '{AWS_SECRET_ACCESS_KEY: "AKIAIOSFODNN7EXAMPLE"}', '{OTHER: "1"}'),
    ("read_only", "true", "false"),
    ("privileged", "false", "true"),
    ("logging", '{driver: "json-file"}', '{driver: "none"}'),
]

DIRECTIVES = ["", "!override ", "!reset "]

MATRIX = [
    (
        f"{field}-{directive.strip() or 'plain'}",
        field,
        base_value,
        directive,
        over_value,
    )
    for field, base_value, over_value in DIRECTIVE_FIELDS
    for directive in DIRECTIVES
]


@pytest.mark.parametrize(
    "case_id,field,base_value,directive,over_value",
    MATRIX,
    ids=[c[0] for c in MATRIX],
)
def test_field_and_directive_matrix_matches_compose(
    case_id: str,
    field: str,
    base_value: str,
    directive: str,
    over_value: str,
    tmp_path: Path,
) -> None:
    """Each merge strategy under each directive agrees with Compose itself."""
    # `!reset` takes null: the directive deletes the key, so the value is moot
    # and a typed one is rejected by the schema.
    value = "null" if directive.startswith("!reset") else over_value
    _write_pair(
        tmp_path,
        f"services:\n  web:\n    image: myapp:1.0\n    {field}: {base_value}\n",
        f"services:\n  web:\n    {field}: {directive}{value}\n",
    )

    truth_file = tmp_path / "truth.yml"
    truth_file.write_text(_compose_config(tmp_path))
    truth_data, truth_lines = load_compose(truth_file)
    expected = _findings_of(truth_data, truth_lines)

    merged = load_merged([tmp_path / "compose.yml", tmp_path / "compose.override.yml"])
    actual = _findings_of(merged.data, merged.lines)

    assert actual == expected, (
        f"{case_id}: merge disagrees with docker compose\n"
        f"  only ours:   {sorted(actual - expected)}\n"
        f"  only theirs: {sorted(expected - actual)}"
    )


def test_three_documents_each_keep_their_own_provenance(tmp_path: Path) -> None:
    """Folding N documents must not credit the accumulator's first file.

    With two documents the base side is a real single file, so a single `path`
    is right and nothing notices it is a simplification. From three on, the
    accumulator is a mixture: `ports` supplied by the middle document was
    attributed to the first, which would point a finding at an unrelated line
    of an unrelated file. Only reachable once more than one overlay is merged —
    which `COMPOSE_FILE` support would do — so it is pinned before it is used.
    """
    (tmp_path / "a.yml").write_text(
        "services:\n  web:\n    image: a:1\n    read_only: true\n"
    )
    (tmp_path / "b.yml").write_text('services:\n  web:\n    ports: ["8080:80"]\n')
    (tmp_path / "c.yml").write_text(
        "services:\n  web:\n"
        '    volumes: ["/var/run/docker.sock:/var/run/docker.sock"]\n'
    )

    merged = load_merged([tmp_path / "a.yml", tmp_path / "b.yml", tmp_path / "c.yml"])

    assert merged.sources["services.web.image"].endswith("a.yml")
    assert merged.sources["services.web.ports[0]"].endswith("b.yml")
    assert merged.sources["services.web.volumes[0]"].endswith("c.yml")
    # And the line travels with the file, not with the accumulator.
    assert merged.lines["services.web.ports[0]"] == 3
    assert merged.lines["services.web.volumes[0]"] == 3


def test_three_document_merge_matches_docker_compose(tmp_path: Path) -> None:
    """The N-document fold agrees with `-f a -f b -f c`, not just with a pair."""
    (tmp_path / "a.yml").write_text(
        "services:\n  web:\n    image: a:1\n"
        "    security_opt: [no-new-privileges:true]\n    read_only: true\n"
    )
    (tmp_path / "b.yml").write_text('services:\n  web:\n    ports: ["8080:80"]\n')
    (tmp_path / "c.yml").write_text("services:\n  web:\n    read_only: false\n")

    result = subprocess.run(
        ["docker", "compose", "-f", "a.yml", "-f", "b.yml", "-f", "c.yml", "config"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        pytest.skip(f"compose rejected the fixture: {result.stderr.strip()[:200]}")
    truth_file = tmp_path / "truth.yml"
    truth_file.write_text(result.stdout)
    truth_data, truth_lines = load_compose(truth_file)

    merged = load_merged([tmp_path / "a.yml", tmp_path / "b.yml", tmp_path / "c.yml"])
    assert _findings_of(merged.data, merged.lines) == _findings_of(
        truth_data, truth_lines
    )
