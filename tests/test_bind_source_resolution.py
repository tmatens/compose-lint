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
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from compose_lint.engine import run_rules
from compose_lint.parser import load_compose, loads

if TYPE_CHECKING:
    from collections.abc import Iterator

# Deeper than any real filesystem, so the climb always lands on "/".
CLIMB = "/".join([".."] * 40)

_HOME = Path.home()
_HOME_IS_UNDER_HOME = str(_HOME) == "/home" or str(_HOME).startswith("/home/")


@pytest.fixture(params=["tmp", "home"])
def base_dir(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Path]:
    """A directory to write the compose file into, at two different roots.

    Resolution makes a finding a function of *where the file sits*: the host
    path a relative source names depends on the compose file's directory, and
    several host-path rules match on prefix. So the same document is not
    guaranteed to score the same under two roots, and a suite that only ever
    writes to one cannot see the difference.

    ``tmp_path`` is always under ``/tmp``. That is what hid a HIGH false
    positive on ``./data`` -- ``/home`` is a CL-0013 member, so a benign
    relative source becomes a finding under one root and not the other, and
    every real user keeps compose files under ``/home``.
    """
    if request.param == "tmp":
        yield tmp_path
        return
    if not _HOME_IS_UNDER_HOME:
        pytest.skip(f"$HOME is {_HOME}, not under /home — nothing to contrast")
    root = Path(tempfile.mkdtemp(dir=_HOME, prefix=".compose-lint-test-"))
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _write(base_dir: Path, body: str) -> Path:
    nested = base_dir / "stack" / "compose"
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


def test_short_syntax_climb_to_root_is_claimed(base_dir: Path) -> None:
    path = _write(
        base_dir,
        f'services:\n  svc:\n    image: nginx\n    volumes: ["{CLIMB}:/host"]\n',
    )
    assert _mount_findings(path).get("svc") == {"CL-0001"}


def test_long_syntax_climb_to_root_is_claimed(base_dir: Path) -> None:
    path = _write(
        base_dir,
        "services:\n  svc:\n    image: nginx\n    volumes:\n"
        f"      - {{type: bind, source: {CLIMB}, target: /host}}\n",
    )
    assert _mount_findings(path).get("svc") == {"CL-0001"}


def test_climb_into_a_root_equivalent_path_is_claimed(base_dir: Path) -> None:
    path = _write(
        base_dir,
        f'services:\n  svc:\n    image: nginx\n    volumes: ["{CLIMB}/etc:/hetc"]\n',
    )
    assert _mount_findings(path).get("svc") == {"CL-0025"}


def test_a_benign_relative_source_is_not_flagged(base_dir: Path) -> None:
    # The common case by far. Resolving must not turn "./data" into a finding.
    path = _write(
        base_dir,
        'services:\n  svc:\n    image: nginx\n    volumes: ["./data:/data"]\n',
    )
    assert _mount_findings(path) == {}


def test_tilde_expands_to_the_home_directory(base_dir: Path) -> None:
    # Verified: Compose mounts $HOME for a "~" source. Under /home, that is
    # CL-0013's.
    home = os.path.expanduser("~")
    path = _write(
        base_dir,
        'services:\n  svc:\n    image: nginx\n    volumes: ["~/.ssh:/keys"]\n',
    )
    data, _ = load_compose(path)
    assert data["services"]["svc"]["volumes"] == [f"{home}/.ssh:/keys"]


def test_tilde_user_is_left_alone(base_dir: Path) -> None:
    # Not because Compose ignores it -- measured on Compose 29.4.3, "~someone/x"
    # becomes "$HOME/someone/x", i.e. it strips the "~" and joins the rest onto
    # the *invoking* user's home, never another account's. Reproducing that
    # would assert a host path out of the linting user's environment for a
    # spelling whose author meant a different account, so no path is claimed.
    path = _write(
        base_dir,
        'services:\n  svc:\n    image: nginx\n    volumes: ["~someone/x:/x"]\n',
    )
    data, _ = load_compose(path)
    assert data["services"]["svc"]["volumes"] == ["~someone/x:/x"]


def test_a_named_volume_is_not_mistaken_for_a_relative_source(base_dir: Path) -> None:
    path = _write(
        base_dir,
        'services:\n  svc:\n    image: nginx\n    volumes: ["pgdata:/var/lib/x"]\n',
    )
    data, _ = load_compose(path)
    assert data["services"]["svc"]["volumes"] == ["pgdata:/var/lib/x"]


def test_an_unresolved_interpolation_is_left_alone(base_dir: Path) -> None:
    # "${DIR}/data" is not a shape Compose reads as a bind, and the parser
    # leaves ${VAR} unresolved by contract.
    path = _write(
        base_dir,
        'services:\n  svc:\n    image: nginx\n    volumes: ["${DIR}/data:/data"]\n',
    )
    data, _ = load_compose(path)
    assert data["services"]["svc"]["volumes"] == ["${DIR}/data:/data"]


def test_absolute_sources_are_untouched(base_dir: Path) -> None:
    path = _write(
        base_dir,
        "services:\n  svc:\n    image: nginx\n"
        '    volumes: ["/etc/localtime:/etc/localtime:ro"]\n',
    )
    data, _ = load_compose(path)
    assert data["services"]["svc"]["volumes"] == ["/etc/localtime:/etc/localtime:ro"]


def test_a_project_data_dir_under_home_is_not_user_data(base_dir: Path) -> None:
    # The shape that made this necessary. Every one of these resolves to an
    # absolute path under the compose file's directory; under /home a descent
    # match on /home turned all of them into HIGH findings.
    for source in ("./data", "./config/nginx.conf", "../shared", "./${SVC}/y"):
        path = _write(
            base_dir / source.replace("/", "_").replace(".", "_").replace("$", ""),
            f'services:\n  svc:\n    image: nginx\n    volumes: ["{source}:/d"]\n',
        )
        assert _mount_findings(path) == {}, source


def test_a_tilde_credential_dir_is_still_claimed(base_dir: Path) -> None:
    # Narrowing /home must not lose the real disclosures. "~/.ssh" expands to
    # $HOME/.ssh, which is a credential directory whatever sits below it.
    path = _write(
        base_dir,
        'services:\n  svc:\n    image: nginx\n    volumes: ["~/.ssh:/keys"]\n',
    )
    if _HOME_IS_UNDER_HOME:
        assert _mount_findings(path).get("svc") == {"CL-0013"}


def test_a_symlinked_directory_resolves_lexically(tmp_path: Path) -> None:
    # Compose resolves a relative source against the project directory *as
    # given*, not against the symlink's target. Verified on Compose 29.4.3:
    # through a symlinked directory, "../etc" is the parent of the link path.
    real = tmp_path / "real" / "deep"
    real.mkdir(parents=True)
    (real / "docker-compose.yml").write_text(
        'services:\n  svc:\n    image: nginx\n    volumes: ["../marker:/m"]\n',
        encoding="utf-8",
    )
    link = tmp_path / "link"
    link.symlink_to(real)

    data, _ = load_compose(link / "docker-compose.yml")
    # Lexical: parent of the *link* path, not of its target.
    assert data["services"]["svc"]["volumes"] == [f"{tmp_path}/marker:/m"]


def test_loads_without_a_base_dir_leaves_sources_as_written() -> None:
    # The fix engine's validation re-parse has no file, so there is nothing to
    # resolve against; leaving the source alone is the correct answer there.
    data, _ = loads(
        'services:\n  svc:\n    image: nginx\n    volumes: ["../../x:/x"]\n'
    )
    assert data["services"]["svc"]["volumes"] == ["../../x:/x"]
