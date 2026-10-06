"""Every read site crossed with every placement of its target, in one table (ADR-038).

A Compose document names other files nine ways: an ``include:`` target, a
cross-file ``extends:`` base, an ``include:`` entry's ``project_directory:``,
an ``env_file:``, the project's own ``.env``, a ``COMPOSE_FILE`` entry in that
``.env``, the Compose file itself when it is a symlink, its
``compose.override.yml`` when that is one, and the discovered
``.compose-lint.yml``. Each is contained by the same two gates — what the path
*says* and where it *resolves* — against one root, the repository holding the
project (``_safe_read.containment_root``). Before ADR-038 the sites had
drifted: a ``..`` path was held to the project directory while a link reached
the run directory, so the same shared file was followed one way and refused
the other.

Each site's coverage used to live in its own test file, written in its own
words, which is how the drift stayed invisible. Here the sites are rows and
the placements are columns, so a site that answers differently from its
neighbours fails a cell. The one deliberate exception is a cell too:
``COMPOSE_FILE`` written with ``..`` stays on the project-directory line
(ADR-038 decision 5), and a link in that list follows the shared root.

Every value here is a synthetic marker.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest

from compose_lint._env_file import env_read_failure
from compose_lint._safe_read import OUT_OF_REACH
from compose_lint._selection import plan_documents
from compose_lint._service_env import Unread, resolve_env_files
from compose_lint.config import ConfigError, load_config
from compose_lint.parser import load_compose_full

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

pytestmark = pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")

FOLLOWED = "followed"
REFUSED_PATH = "refused: the path leaves"  # the lexical gate
REFUSED_LINK = "refused: the link leaves"  # the physical gate
REFUSED = "refused"  # a site whose message does not say which gate

MARKER = "cl-containment-matrix-marker"
PLAIN = "services:\n  web:\n    image: nginx:1.27\n"
PART = "services:\n  shared:\n    image: nginx:1.27\n    privileged: true\n"
BASE = "services:\n  base:\n    image: nginx:1.27\n    privileged: true\n"
OVERLAY = "services:\n  web:\n    privileged: true\n"
BY_TAG = "services:\n  web:\n    image: nginx:${TAG:-none}\n"
DOTENV = "TAG=1.27\n"
ENV_FILE = f"DB_PASSWORD={MARKER}\n"
POLICY = "rules:\n  CL-0002:\n    enabled: false\n"


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@dataclass(frozen=True)
class Tree:
    """``outside/`` beside a repository whose project sits in ``repo/svc/``."""

    root: Path

    @property
    def outside(self) -> Path:
        return self.root / "outside"

    @property
    def repo(self) -> Path:
        return self.root / "repo"

    @property
    def project(self) -> Path:
        return self.repo / "svc"

    def build(self) -> None:
        (self.repo / ".git").mkdir(parents=True)
        self.project.mkdir()
        self.outside.mkdir()


@dataclass(frozen=True)
class Placement:
    """Where a target lives, how the project spells it, and what must happen."""

    name: str
    # Where the target is written, relative to the tree root.
    home: str
    # How the document refers to it, relative to the project directory, with
    # ``{name}`` for the target's own name; ``None`` means "through a link
    # named ``linked-{name}`` in the project directory".
    spelling: str | None
    expected: str
    # The spelling is an absolute path (``home`` is resolved to one).
    absolute: bool = False

    @property
    def by_link(self) -> bool:
        return self.spelling is None

    def place(self, tree: Tree, name: str, content: str, *, directory: bool) -> str:
        """Write the target and return the reference the document writes."""
        target = tree.root / self.home / name
        if directory:
            _write(target / ".env", content)
        else:
            _write(target, content)
        if self.by_link:
            link = tree.project / f"linked-{name}"
            link.symlink_to(target, target_is_directory=directory)
            return link.name
        if self.absolute:
            return str(target)
        assert self.spelling is not None
        return self.spelling.format(name=name)


PLACEMENTS = (
    Placement("in-project", "repo/svc/sub", "sub/{name}", FOLLOWED),
    Placement("in-repo-by-path", "repo/shared", "../shared/{name}", FOLLOWED),
    Placement("in-repo-by-link", "repo/shared", None, FOLLOWED),
    Placement("outside-by-path", "outside", "../../outside/{name}", REFUSED_PATH),
    Placement("outside-by-link", "outside", None, REFUSED_LINK),
    Placement("git-dir-by-path", "repo/.git", "../.git/{name}", REFUSED_PATH),
    Placement("git-dir-by-link", "repo/.git", None, REFUSED_LINK),
    Placement("absolute", "outside", "", REFUSED_PATH, absolute=True),
)
BY_NAME = {p.name: p for p in PLACEMENTS}


@dataclass(frozen=True)
class Site:
    """One way a document names a file: how to build it, how to read the result."""

    name: str
    # Builds the project around ``reference`` and returns the primary file.
    build: Callable[[Tree, str], Path]
    observe: Callable[[Tree, Path], str]
    # The content the target carries at this site.
    content: str
    directory: bool = False
    # A site that is only ever a link (the file's own name is fixed) skips the
    # path spellings; its link cells still run.
    link_only: bool = False
    # A site whose refusal message does not say which gate refused it.
    blind_to_gate: bool = False
    # Cells this site answers differently from the shared root, by decision.
    exceptions: dict[str, str] | None = None
    # Where the run starts. The default is *above* the repository, so a cell
    # passing proves the root came from the ``.git`` marker, not from cwd.
    cwd: Callable[[Tree], Path] = lambda tree: tree.root


def _gate(messages: list[str]) -> str:
    joined = "\n".join(messages)
    if OUT_OF_REACH in joined or "links to a file outside" in joined:
        return REFUSED_LINK
    if "outside the repository" in joined or "leaves the repository" in joined:
        return REFUSED_PATH
    raise AssertionError(f"refused for a reason the matrix does not know: {joined}")


# --- include: ----------------------------------------------------------------


def _build_include(tree: Tree, reference: str) -> Path:
    return _write(tree.project / "compose.yml", f"include:\n  - {reference}\n{PLAIN}")


def _observe_include(tree: Tree, primary: Path) -> str:
    loaded = load_compose_full(primary)
    if "shared" in loaded.data["services"]:
        assert loaded.gaps == ()
        return FOLLOWED
    return _gate(list(loaded.gaps))


# --- extends: {file:} ----------------------------------------------------------


def _build_extends(tree: Tree, reference: str) -> Path:
    return _write(
        tree.project / "compose.yml",
        f"services:\n  web:\n    extends:\n      file: {reference}\n"
        "      service: base\n",
    )


def _observe_extends(tree: Tree, primary: Path) -> str:
    loaded = load_compose_full(primary)
    if loaded.data["services"]["web"].get("privileged") is True:
        assert loaded.gaps == ()
        return FOLLOWED
    return _gate(list(loaded.gaps))


# --- include: entry's project_directory: ---------------------------------------


def _build_project_directory(tree: Tree, reference: str) -> Path:
    _write(
        tree.project / "sub" / "part.yml",
        "services:\n  part:\n    image: nginx:${TAG:-none}\n",
    )
    return _write(
        tree.project / "compose.yml",
        f"include:\n  - path: sub/part.yml\n    project_directory: {reference}\n"
        f"{PLAIN}",
    )


def _observe_project_directory(tree: Tree, primary: Path) -> str:
    loaded = load_compose_full(primary)
    part = loaded.data["services"].get("part")
    if part is not None and part["image"] == "nginx:1.27":
        assert loaded.gaps == ()
        return FOLLOWED
    return _gate(list(loaded.gaps))


# --- env_file: ------------------------------------------------------------------


def _build_env_file(tree: Tree, reference: str) -> Path:
    return _write(
        tree.project / "compose.yml",
        f"services:\n  web:\n    image: nginx:1.27\n    env_file: {reference}\n",
    )


def _observe_env_file(tree: Tree, primary: Path) -> str:
    loaded = load_compose_full(primary)
    resolved = resolve_env_files(loaded.data, primary.parent)["web"]
    if [key.key for key in resolved.available] == ["DB_PASSWORD"]:
        assert resolved.unread == ()
        return FOLLOWED
    (unread,) = resolved.unread
    assert unread.reason is Unread.OUTSIDE_PROJECT
    return REFUSED


# --- the project's .env ------------------------------------------------------------


def _build_dotenv(tree: Tree, reference: str) -> Path:
    # The `.env` has one name, so the placement's link is renamed into it.
    (tree.project / reference).rename(tree.project / ".env")
    return _write(tree.project / "compose.yml", BY_TAG)


def _observe_dotenv(tree: Tree, primary: Path) -> str:
    loaded = load_compose_full(primary)
    if loaded.data["services"]["web"]["image"] == "nginx:1.27":
        assert env_read_failure(primary.parent) is None
        return FOLLOWED
    failure = env_read_failure(primary.parent)
    assert failure is not None
    return _gate([failure])


# --- COMPOSE_FILE in that .env ---------------------------------------------------


def _build_compose_file(tree: Tree, reference: str) -> Path:
    _write(tree.project / ".env", f"COMPOSE_FILE=compose.yml:{reference}\n")
    return _write(tree.project / "compose.yml", PLAIN)


def _observe_compose_file(tree: Tree, primary: Path) -> str:
    selection = plan_documents([str(primary)])
    (group,) = selection.groups
    if len(group.paths) == 2:
        assert selection.gaps == ()
        return FOLLOWED
    (gap,) = selection.gaps
    assert "COMPOSE_FILE names" in gap[1]
    return REFUSED


# --- the Compose file itself, as a link -------------------------------------------


def _build_compose_link(tree: Tree, reference: str) -> Path:
    (tree.project / reference).rename(tree.project / "compose.yml")
    return tree.project / "compose.yml"


def _observe_compose_link(tree: Tree, primary: Path) -> str:
    selection = plan_documents([str(primary)])
    if selection.groups:
        assert selection.gaps == ()
        return FOLLOWED
    (gap,) = selection.gaps
    return _gate([gap[1]])


# --- compose.override.yml, as a link ------------------------------------------------


def _build_override_link(tree: Tree, reference: str) -> Path:
    (tree.project / reference).rename(tree.project / "compose.override.yml")
    return _write(tree.project / "compose.yml", PLAIN)


def _observe_override_link(tree: Tree, primary: Path) -> str:
    selection = plan_documents([str(primary)])
    (group,) = selection.groups
    if group.overlays:
        assert selection.gaps == ()
        return FOLLOWED
    (gap,) = selection.gaps
    return _gate([gap[1]])


# --- the discovered .compose-lint.yml ------------------------------------------


def _build_policy_link(tree: Tree, reference: str) -> Path:
    (tree.project / reference).rename(tree.project / ".compose-lint.yml")
    return _write(tree.project / "compose.yml", PLAIN)


def _observe_policy_link(tree: Tree, primary: Path) -> str:
    try:
        disabled, _, _ = load_config()
    except ConfigError as exc:
        return _gate([str(exc)])
    assert "CL-0002" in disabled
    return FOLLOWED


SITES = (
    Site("include", _build_include, _observe_include, PART),
    Site("extends", _build_extends, _observe_extends, BASE),
    Site(
        "project_directory",
        _build_project_directory,
        _observe_project_directory,
        DOTENV,
        directory=True,
    ),
    Site("env_file", _build_env_file, _observe_env_file, ENV_FILE, blind_to_gate=True),
    Site("dotenv", _build_dotenv, _observe_dotenv, DOTENV, link_only=True),
    Site(
        "compose_file",
        _build_compose_file,
        _observe_compose_file,
        OVERLAY,
        blind_to_gate=True,
        # ADR-038 decision 5: what a COMPOSE_FILE entry *says* is still held to
        # the project directory, because its refusal rests on ADR-026 §4 (the
        # `.env` choosing what the run lints), not on leakage.
        exceptions={"in-repo-by-path": REFUSED},
    ),
    Site(
        "compose_link",
        _build_compose_link,
        _observe_compose_link,
        PLAIN,
        link_only=True,
    ),
    Site(
        "override_link",
        _build_override_link,
        _observe_override_link,
        OVERLAY,
        link_only=True,
    ),
    Site(
        "policy_link",
        _build_policy_link,
        _observe_policy_link,
        POLICY,
        link_only=True,
        # Discovered in the working directory, so the run starts in the
        # project; its root is that directory's repository, like every other.
        cwd=lambda tree: tree.project,
    ),
)


def _cells() -> list[tuple[Site, Placement]]:
    return [
        (site, placement)
        for site in SITES
        for placement in PLACEMENTS
        if placement.by_link or not site.link_only
    ]


@pytest.mark.parametrize(
    ("site", "placement"),
    _cells(),
    ids=[f"{site.name}/{placement.name}" for site, placement in _cells()],
)
def test_every_site_answers_the_same_way(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, site: Site, placement: Placement
) -> None:
    tree = Tree(tmp_path)
    tree.build()
    reference = placement.place(
        tree,
        "cfg" if site.directory else "target.yml",
        site.content,
        directory=site.directory,
    )
    primary = site.build(tree, reference)
    monkeypatch.chdir(site.cwd(tree))

    observed = site.observe(tree, primary)

    expected = (site.exceptions or {}).get(placement.name, placement.expected)
    if site.blind_to_gate and expected != FOLLOWED:
        expected = REFUSED
    assert observed == expected, f"{site.name} at {placement.name}"


def test_the_table_covers_every_site_and_placement() -> None:
    """A new site or placement joins the matrix, not a file of its own."""
    assert {s.name for s in SITES} == {
        "include",
        "extends",
        "project_directory",
        "env_file",
        "dotenv",
        "compose_file",
        "compose_link",
        "override_link",
        "policy_link",
    }
    assert {p.name for p in PLACEMENTS} == {
        "in-project",
        "in-repo-by-path",
        "in-repo-by-link",
        "outside-by-path",
        "outside-by-link",
        "git-dir-by-path",
        "git-dir-by-link",
        "absolute",
    }
    # Exactly one cell is decided differently from the shared root, and it is
    # written down as such.
    exceptions = [(s.name, cell) for s in SITES for cell in (s.exceptions or {})]
    assert exceptions == [("compose_file", "in-repo-by-path")]
