"""An `extends:` base resolves only the service it was opened for.

Compose 5.5.0 follows the `extends:` chain of the service a document names,
never its siblings'. compose-lint resolved every service in the base file, so:

- a sibling whose own `extends:` names its file for another service
  (`funnel-prod: {extends: {file: services.yml, service: funnel}}`) was
  followed back into the same file and reported as a cycle; and
- a sibling with a broken `extends:` was a coverage gap in a project that
  never uses it.

Both exited 2 on projects Compose accepts. A real cycle is still a gap.
Measured on Compose 5.5.0 for each case.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from compose_lint.parser import load_compose_full

if TYPE_CHECKING:
    from pathlib import Path


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_a_self_file_chain_is_not_a_cycle(tmp_path: Path) -> None:
    _write(
        tmp_path / "base.yml",
        "services:\n"
        "  funnel:\n    image: nginx:1.27\n    privileged: true\n"
        "  funnel-prod:\n"
        "    extends:\n      file: base.yml\n      service: funnel\n"
        "    read_only: true\n",
    )
    compose = _write(
        tmp_path / "compose.yaml",
        "services:\n  app:\n    extends:\n      file: base.yml\n"
        "      service: funnel-prod\n",
    )
    loaded = load_compose_full(compose)
    assert loaded.gaps == ()
    app = loaded.data["services"]["app"]
    assert app["privileged"] is True
    assert app["read_only"] is True


def test_a_broken_sibling_is_not_a_gap(tmp_path: Path) -> None:
    _write(
        tmp_path / "base.yml",
        "services:\n  funnel:\n    image: nginx:1.27\n"
        "  other:\n    extends:\n      file: missing.yml\n      service: x\n",
    )
    compose = _write(
        tmp_path / "compose.yaml",
        "services:\n  app:\n    extends:\n      file: base.yml\n"
        "      service: funnel\n",
    )
    assert load_compose_full(compose).gaps == ()


def test_an_in_file_ancestor_is_still_resolved(tmp_path: Path) -> None:
    """The requested service's own in-file chain is followed, cross-file
    hops included."""
    _write(tmp_path / "far.yml", "services:\n  root:\n    cap_add: [SYS_ADMIN]\n")
    _write(
        tmp_path / "base.yml",
        "services:\n"
        "  mid:\n    image: nginx:1.27\n"
        "    extends:\n      file: far.yml\n      service: root\n"
        "  top:\n    extends: mid\n",
    )
    compose = _write(
        tmp_path / "compose.yaml",
        "services:\n  app:\n    extends:\n      file: base.yml\n      service: top\n",
    )
    loaded = load_compose_full(compose)
    assert loaded.gaps == ()
    assert loaded.data["services"]["app"]["cap_add"] == ["SYS_ADMIN"]


def test_a_real_cycle_is_still_a_gap(tmp_path: Path) -> None:
    _write(
        tmp_path / "a.yml",
        "services:\n  s1:\n    image: nginx:1.27\n"
        "    extends:\n      file: b.yml\n      service: s2\n",
    )
    _write(
        tmp_path / "b.yml",
        "services:\n  s2:\n    image: nginx:1.27\n"
        "    extends:\n      file: a.yml\n      service: s1\n",
    )
    compose = _write(
        tmp_path / "compose.yaml",
        "services:\n  app:\n    extends:\n      file: a.yml\n      service: s1\n",
    )
    (gap,) = load_compose_full(compose).gaps
    assert "returns to a base" in gap
