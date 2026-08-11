"""Relative and ``~`` bind sources resolve to the host paths they name.

Compose resolves a relative source against the directory holding the compose
file and expands a leading ``~``; both were verified against Docker Compose
29.4.3, where a long-syntax bind with twelve ``..`` segments mounted the host
root filesystem. Left as written, neither shape reached the host-path rules --
``../../../..`` matches no entry in any path list, and the short-syntax pattern
does not recognise a non-absolute source as a bind at all -- so a whole-root
bind spelled that way produced a clean pass.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from compose_lint.engine import run_rules
from compose_lint.parser import load_compose, loads

if TYPE_CHECKING:
    from pathlib import Path

# Deeper than any real filesystem, so the climb always lands on "/".
CLIMB = "/".join([".."] * 40)


def _write(tmp_path: Path, body: str) -> Path:
    nested = tmp_path / "stack" / "compose"
    nested.mkdir(parents=True)
    path = nested / "docker-compose.yml"
    path.write_text(body, encoding="utf-8")
    return path


def _mount_findings(path: Path) -> dict[str, set[str]]:
    data, lines = load_compose(path)
    out: dict[str, set[str]] = {}
    for finding in run_rules(data, lines):
        if finding.rule_id in {"CL-0001", "CL-0013", "CL-0025"}:
            out.setdefault(finding.service or "", set()).add(finding.rule_id)
    return out


def test_short_syntax_climb_to_root_is_claimed(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        f'services:\n  svc:\n    image: nginx\n    volumes: ["{CLIMB}:/host"]\n',
    )
    assert _mount_findings(path).get("svc") == {"CL-0001"}


def test_long_syntax_climb_to_root_is_claimed(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "services:\n  svc:\n    image: nginx\n    volumes:\n"
        f"      - {{type: bind, source: {CLIMB}, target: /host}}\n",
    )
    assert _mount_findings(path).get("svc") == {"CL-0001"}


def test_climb_into_a_root_equivalent_path_is_claimed(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        f'services:\n  svc:\n    image: nginx\n    volumes: ["{CLIMB}/etc:/hetc"]\n',
    )
    assert _mount_findings(path).get("svc") == {"CL-0025"}


def test_a_benign_relative_source_is_not_flagged(tmp_path: Path) -> None:
    # The common case by far. Resolving must not turn "./data" into a finding.
    path = _write(
        tmp_path,
        'services:\n  svc:\n    image: nginx\n    volumes: ["./data:/data"]\n',
    )
    assert _mount_findings(path) == {}


def test_tilde_expands_to_the_home_directory(tmp_path: Path) -> None:
    # Verified: Compose mounts $HOME for a "~" source. Under /home, that is
    # CL-0013's.
    home = os.path.expanduser("~")
    path = _write(
        tmp_path,
        'services:\n  svc:\n    image: nginx\n    volumes: ["~/.ssh:/keys"]\n',
    )
    data, _ = load_compose(path)
    assert data["services"]["svc"]["volumes"] == [f"{home}/.ssh:/keys"]


def test_tilde_user_is_left_alone(tmp_path: Path) -> None:
    # Compose does not expand it, and guessing another account's home would
    # invent a host path.
    path = _write(
        tmp_path,
        'services:\n  svc:\n    image: nginx\n    volumes: ["~someone/x:/x"]\n',
    )
    data, _ = load_compose(path)
    assert data["services"]["svc"]["volumes"] == ["~someone/x:/x"]


def test_a_named_volume_is_not_mistaken_for_a_relative_source(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        'services:\n  svc:\n    image: nginx\n    volumes: ["pgdata:/var/lib/x"]\n',
    )
    data, _ = load_compose(path)
    assert data["services"]["svc"]["volumes"] == ["pgdata:/var/lib/x"]


def test_an_unresolved_interpolation_is_left_alone(tmp_path: Path) -> None:
    # "${DIR}/data" is not a shape Compose reads as a bind, and the parser
    # leaves ${VAR} unresolved by contract.
    path = _write(
        tmp_path,
        'services:\n  svc:\n    image: nginx\n    volumes: ["${DIR}/data:/data"]\n',
    )
    data, _ = load_compose(path)
    assert data["services"]["svc"]["volumes"] == ["${DIR}/data:/data"]


def test_absolute_sources_are_untouched(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "services:\n  svc:\n    image: nginx\n"
        '    volumes: ["/etc/localtime:/etc/localtime:ro"]\n',
    )
    data, _ = load_compose(path)
    assert data["services"]["svc"]["volumes"] == ["/etc/localtime:/etc/localtime:ro"]


def test_loads_without_a_base_dir_leaves_sources_as_written() -> None:
    # The fix engine's validation re-parse has no file, so there is nothing to
    # resolve against; leaving the source alone is the correct answer there.
    data, _ = loads(
        'services:\n  svc:\n    image: nginx\n    volumes: ["../../x:/x"]\n'
    )
    assert data["services"]["svc"]["volumes"] == ["../../x:/x"]
