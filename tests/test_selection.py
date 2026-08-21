"""Tests for which documents a run grades (ADR-026).

The behaviour under test is a security boundary as much as a feature: a `.env`
is content inside the artifact being linted, so what it is allowed to change
about the lint's own scope is the whole question. ``TestAddOnly`` is that
boundary stated as tests.
"""

from __future__ import annotations

import os
from pathlib import PurePath
from typing import TYPE_CHECKING

import pytest

from compose_lint._selection import plan_documents

if TYPE_CHECKING:
    from pathlib import Path

BASE = "services:\n  web:\n    image: i\n"
OVERLAY = "services:\n  web:\n    privileged: true\n"
PROD = "services:\n  web:\n    volumes: ['/var/run/docker.sock:/var/run/docker.sock']\n"


def os_name(path: str) -> str:
    """A group's paths keep the caller's spelling; compare by basename."""
    return PurePath(path).name


def write(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.write_text(text, encoding="utf-8", newline="")
    return path


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A directory with a base, an overlay, and a prod document."""
    write(tmp_path, "compose.yml", BASE)
    write(tmp_path, "compose.override.yml", OVERLAY)
    write(tmp_path, "compose.prod.yml", PROD)
    return tmp_path


@pytest.fixture
def in_project(project: Path) -> Path:
    """Run from inside the project, which is what bare discovery means."""
    previous = os.getcwd()
    os.chdir(project)
    try:
        yield project
    finally:
        os.chdir(previous)


class TestDiscovery:
    """No file named: the pre-ADR-026 behaviour, unchanged."""

    def test_pairs_a_base_with_its_override(self, in_project: Path) -> None:
        selection = plan_documents([])
        assert [g.paths for g in selection.groups] == [
            ["compose.yml", "compose.override.yml"]
        ]
        assert not selection.groups[0].selected_by_env

    def test_paths_stay_relative(self, in_project: Path) -> None:
        """The report names files the way the user does."""
        assert [g.primary for g in plan_documents([]).groups] == ["compose.yml"]

    def test_no_overlay_when_none_sits_beside(self, tmp_path: Path) -> None:
        write(tmp_path, "compose.yml", BASE)
        previous = os.getcwd()
        os.chdir(tmp_path)
        try:
            assert [g.paths for g in plan_documents([]).groups] == [["compose.yml"]]
        finally:
            os.chdir(previous)

    def test_no_merge_overrides_leaves_the_base_alone(self, in_project: Path) -> None:
        selection = plan_documents([], merge_overrides=False)
        assert [g.paths for g in selection.groups] == [["compose.yml"]]

    def test_nothing_found_is_an_empty_selection(self, tmp_path: Path) -> None:
        previous = os.getcwd()
        os.chdir(tmp_path)
        try:
            assert plan_documents([]).groups == ()
        finally:
            os.chdir(previous)


class TestComposeFile:
    """A `.env` that names a file list replaces discovery, as Compose does."""

    def test_selects_the_named_documents(self, in_project: Path) -> None:
        write(in_project, ".env", "COMPOSE_FILE=compose.yml:compose.prod.yml\n")
        selection = plan_documents([])
        assert [g.paths for g in selection.groups] == [
            ["compose.yml", "compose.prod.yml"]
        ]

    def test_suppresses_the_override_merge(self, in_project: Path) -> None:
        """The bug ADR-026 exists to fix: Compose does not load the override
        when COMPOSE_FILE is set, so neither may we."""
        write(in_project, ".env", "COMPOSE_FILE=compose.yml:compose.prod.yml\n")
        merged = plan_documents([]).groups[0].paths
        assert "compose.override.yml" not in merged

    def test_records_that_the_env_chose(self, in_project: Path) -> None:
        """The report must not claim Compose merges these automatically."""
        write(in_project, ".env", "COMPOSE_FILE=compose.yml:compose.prod.yml\n")
        assert plan_documents([]).groups[0].selected_by_env

    def test_announces_what_it_selected(self, in_project: Path) -> None:
        write(in_project, ".env", "COMPOSE_FILE=compose.yml:compose.prod.yml\n")
        notes = " ".join(plan_documents([]).notes)
        assert "COMPOSE_FILE selects" in notes
        assert "compose.prod.yml" in notes

    def test_honours_a_custom_separator(self, in_project: Path) -> None:
        write(
            in_project,
            ".env",
            "COMPOSE_PATH_SEPARATOR=,\nCOMPOSE_FILE=compose.yml,compose.prod.yml\n",
        )
        assert [g.paths for g in plan_documents([]).groups] == [
            ["compose.yml", "compose.prod.yml"]
        ]

    def test_a_single_entry_needs_no_merge(self, in_project: Path) -> None:
        write(in_project, ".env", "COMPOSE_FILE=compose.prod.yml\n")
        assert [g.paths for g in plan_documents([]).groups] == [["compose.prod.yml"]]

    def test_order_is_the_lists_order(self, in_project: Path) -> None:
        """Merge order decides which value wins, so it is not incidental."""
        write(in_project, ".env", "COMPOSE_FILE=compose.prod.yml:compose.yml\n")
        assert [g.paths for g in plan_documents([]).groups] == [
            ["compose.prod.yml", "compose.yml"]
        ]

    def test_no_env_ignores_it_entirely(self, in_project: Path) -> None:
        write(in_project, ".env", "COMPOSE_FILE=compose.yml:compose.prod.yml\n")
        selection = plan_documents([], read_env_files=False)
        assert [g.paths for g in selection.groups] == [
            ["compose.yml", "compose.override.yml"]
        ]


class TestRefusals:
    """A refused list falls back rather than being honoured in part.

    Grading half a COMPOSE_FILE would grade a set Compose never loads, which is
    the failure the whole mechanism exists to remove.
    """

    def test_an_entry_outside_the_project_is_refused(self, in_project: Path) -> None:
        write(in_project, ".env", "COMPOSE_FILE=compose.yml:../escape.yml\n")
        selection = plan_documents([])
        assert [g.paths for g in selection.groups] == [
            ["compose.yml", "compose.override.yml"]
        ]
        assert "outside the project directory" in " ".join(selection.notes)

    def test_an_absolute_entry_is_refused(self, in_project: Path) -> None:
        """The .env must not be able to point the linter at an arbitrary file."""
        write(in_project, ".env", "COMPOSE_FILE=/etc/passwd\n")
        selection = plan_documents([])
        assert selection.groups[0].paths == ["compose.yml", "compose.override.yml"]
        assert "/etc/passwd" not in str(selection.groups)
        assert "ignored" in " ".join(selection.notes)

    def test_a_windows_drive_entry_is_refused(self, in_project: Path) -> None:
        write(in_project, ".env", "COMPOSE_FILE=C:/windows/system32/x.yml\n")
        selection = plan_documents([])
        assert selection.groups[0].paths == ["compose.yml", "compose.override.yml"]

    def test_a_missing_entry_is_refused(self, in_project: Path) -> None:
        """Compose does not start on this either, so nothing is invented."""
        write(in_project, ".env", "COMPOSE_FILE=compose.yml:absent.yml\n")
        selection = plan_documents([])
        assert selection.groups[0].paths == ["compose.yml", "compose.override.yml"]
        assert "ignored" in " ".join(selection.notes)

    def test_an_empty_value_changes_nothing(self, in_project: Path) -> None:
        write(in_project, ".env", "COMPOSE_FILE=\n")
        assert plan_documents([]).groups[0].paths == [
            "compose.yml",
            "compose.override.yml",
        ]


class TestAddOnly:
    """ADR-026 section 4: a `.env` may expand the lint set, never shrink it.

    A runtime does what it is told; a gate must not let the artifact under
    inspection define its own scope. Both first-party integrations pass explicit
    file lists, so this is the path that matters in CI.
    """

    def test_a_named_file_in_the_list_is_graded_as_the_project(
        self, project: Path
    ) -> None:
        write(project, ".env", "COMPOSE_FILE=compose.yml:compose.prod.yml\n")
        selection = plan_documents([str(project / "compose.yml")])
        assert [os_name(p) for p in selection.groups[0].paths] == [
            "compose.yml",
            "compose.prod.yml",
        ]

    def test_a_named_file_absent_from_the_list_is_still_graded(
        self, project: Path
    ) -> None:
        """The evasion this rule exists to stop: a committed `.env` must not be
        able to remove a file from the gate's scope."""
        write(project, "extra.yml", BASE)
        write(project, ".env", "COMPOSE_FILE=compose.yml\n")
        selection = plan_documents([str(project / "extra.yml")])
        assert [os_name(p) for p in selection.groups[0].paths] == ["extra.yml"]
        assert "does not include this file" in " ".join(selection.notes)
        assert "Nothing was skipped" in " ".join(selection.notes)

    def test_a_decoy_cannot_shrink_a_multi_file_gate(self, project: Path) -> None:
        write(project, "decoy.yml", BASE)
        write(project, ".env", "COMPOSE_FILE=decoy.yml\n")
        named = [str(project / "compose.yml"), str(project / "compose.prod.yml")]
        graded = {os_name(p) for g in plan_documents(named).groups for p in g.paths}
        assert {"compose.yml", "compose.prod.yml"} <= graded

    def test_a_file_is_not_graded_twice(self, project: Path) -> None:
        """Naming both halves of one project lints the project once."""
        write(project, ".env", "COMPOSE_FILE=compose.yml:compose.prod.yml\n")
        named = [str(project / "compose.yml"), str(project / "compose.prod.yml")]
        selection = plan_documents(named)
        assert len(selection.groups) == 1


class TestNamedWithoutEnv:
    """Explicit paths with no `.env` keep behaving exactly as before."""

    def test_pairs_with_the_sibling_override(self, project: Path) -> None:
        selection = plan_documents([str(project / "compose.yml")])
        assert [os_name(p) for p in selection.groups[0].paths] == [
            "compose.yml",
            "compose.override.yml",
        ]

    def test_an_overlay_named_explicitly_is_consumed_once(self, project: Path) -> None:
        """A shell glob expands to both halves; the overlay must not also be
        graded standalone, where its absence findings would be false."""
        named = [str(project / "compose.yml"), str(project / "compose.override.yml")]
        selection = plan_documents(named)
        assert len(selection.groups) == 1
        assert selection.is_consumed(str(project / "compose.override.yml"))

    def test_a_non_canonical_name_gets_no_overlay(self, project: Path) -> None:
        selection = plan_documents([str(project / "compose.prod.yml")])
        assert [os_name(p) for p in selection.groups[0].paths] == ["compose.prod.yml"]
