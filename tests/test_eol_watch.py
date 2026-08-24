"""scripts/eol_watch.py — the pure logic, offline.

The script's contract is three-valued (0 nothing due / 1 due / 2 cannot
answer), and the dangerous failure is the third case masquerading as the
first: a stale declaration or an unparseable floor silently reporting
"nothing due". These tests pin the loud-failure paths as hard as the
happy paths.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import pathlib
import sys

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "eol_watch",
    pathlib.Path(__file__).resolve().parent.parent / "scripts" / "eol_watch.py",
)
assert _SPEC is not None and _SPEC.loader is not None
eol_watch = importlib.util.module_from_spec(_SPEC)
sys.modules["eol_watch"] = eol_watch
_SPEC.loader.exec_module(eol_watch)

TODAY = dt.date(2026, 8, 23)


def _python_payload() -> list[dict[str, object]]:
    return [
        {"cycle": "3.15", "releaseDate": "2026-10-01", "eol": "2031-10-31"},
        {"cycle": "3.14", "releaseDate": "2025-10-07", "eol": "2030-10-31"},
        {"cycle": "3.11", "releaseDate": "2022-10-24", "eol": "2027-10-31"},
        {"cycle": "3.10", "releaseDate": "2021-10-04", "eol": "2026-10-31"},
    ]


class TestPythonFloor:
    def test_reads_the_floor(self) -> None:
        text = '[project]\nrequires-python = ">=3.11"\n'
        assert eol_watch.python_floor(text) == "3.11"

    def test_unknown_spec_form_fails_loudly(self) -> None:
        """A form the regex cannot read must raise, never guess.

        `>=3.11,<4` would silently become "no watch on the floor" if the
        parse returned None anywhere — the stale-anchor failure mode.
        """
        text = '[project]\nrequires-python = ">=3.11,<4"\n'
        with pytest.raises(ValueError, match="requires-python"):
            eol_watch.python_floor(text)


class TestCiMatrix:
    def test_reads_the_matrix(self) -> None:
        text = '        python-version: ["3.11", "3.12", "3.13", "3.14"]\n'
        assert eol_watch.ci_matrix(text) == ["3.11", "3.12", "3.13", "3.14"]

    def test_missing_matrix_fails_loudly(self) -> None:
        with pytest.raises(ValueError, match="matrix"):
            eol_watch.ci_matrix("jobs: {}\n")


class TestAnchor:
    def test_stale_declaration_fails_loudly(self) -> None:
        watch = eol_watch.Watch(
            "debian", "13", "base", anchor_file="Dockerfile", anchor_pattern=r"trixie"
        )
        with pytest.raises(ValueError, match="stale"):
            eol_watch.check_anchor(watch, "FROM debian:forky-slim\n")

    def test_matching_anchor_passes(self) -> None:
        watch = eol_watch.Watch(
            "debian", "13", "base", anchor_file="Dockerfile", anchor_pattern=r"trixie"
        )
        eol_watch.check_anchor(watch, "FROM debian:trixie-slim\n")


class TestCheckEol:
    def test_far_eol_is_not_due(self) -> None:
        watch = eol_watch.Watch("python", "3.11", "floor")
        assert eol_watch.check_eol(watch, _python_payload(), TODAY) is None

    def test_eol_inside_window_is_due(self) -> None:
        watch = eol_watch.Watch("python", "3.10", "floor")
        finding = eol_watch.check_eol(watch, _python_payload(), TODAY)
        assert finding is not None
        assert "3.10" in finding.headline
        assert "2026-10-31" in finding.headline

    def test_past_eol_says_so(self) -> None:
        watch = eol_watch.Watch("python", "3.10", "floor")
        finding = eol_watch.check_eol(watch, _python_payload(), dt.date(2026, 12, 1))
        assert finding is not None
        assert "ago" in finding.headline

    def test_unscheduled_eol_is_not_due(self) -> None:
        """endoflife.date uses `false` for "no EOL scheduled" — not a date."""
        watch = eol_watch.Watch("x", "1", "y")
        assert eol_watch.check_eol(watch, [{"cycle": "1", "eol": False}], TODAY) is None

    def test_unknown_cycle_fails_loudly(self) -> None:
        watch = eol_watch.Watch("python", "9.9", "floor")
        with pytest.raises(ValueError, match="9.9"):
            eol_watch.check_eol(watch, _python_payload(), TODAY)


class TestNewPython:
    def test_released_minor_missing_from_matrix_is_reported(self) -> None:
        found = eol_watch.check_new_python(
            _python_payload(), ["3.11", "3.12", "3.13"], TODAY
        )
        # 3.14 released 2025-10, absent, well past the 3-month window. 3.10
        # is also absent but sits below the matrix ceiling — dropped, not
        # pending — so it must NOT report here.
        headlines = " ".join(f.headline for f in found)
        assert "Python 3.14" in headlines
        assert "OVERDUE" in headlines
        assert "3.10" not in headlines

    def test_future_minor_is_ignored(self) -> None:
        found = eol_watch.check_new_python(
            _python_payload(), ["3.10", "3.11", "3.14"], dt.date(2026, 9, 1)
        )
        assert all("3.15" not in f.headline for f in found)

    def test_fresh_minor_is_reported_without_overdue(self) -> None:
        found = eol_watch.check_new_python(
            _python_payload(), ["3.10", "3.11", "3.14"], dt.date(2026, 10, 15)
        )
        (f,) = [f for f in found if "3.15" in f.headline]
        assert "OVERDUE" not in f.headline

    def test_full_matrix_reports_nothing(self) -> None:
        assert (
            eol_watch.check_new_python(
                _python_payload(), ["3.10", "3.11", "3.14", "3.15"], TODAY
            )
            == []
        )


class TestAgainstTheRealRepo:
    """The live declarations stay parseable and anchored, offline."""

    def test_floor_parses(self) -> None:
        text = (eol_watch.REPO / "pyproject.toml").read_text()
        assert eol_watch.python_floor(text)

    def test_matrix_parses_and_contains_floor(self) -> None:
        floor = eol_watch.python_floor((eol_watch.REPO / "pyproject.toml").read_text())
        matrix = eol_watch.ci_matrix(
            (eol_watch.REPO / ".github/workflows/ci.yml").read_text()
        )
        assert floor in matrix

    def test_declared_anchors_hold(self) -> None:
        """Every anchored Watch in the real declaration list still matches.

        Iterates build_watches() itself rather than a copy, so adding a
        watch with a bad anchor fails here before the monthly run does."""
        floor = eol_watch.python_floor((eol_watch.REPO / "pyproject.toml").read_text())
        anchored = [w for w in eol_watch.build_watches(floor) if w.anchor_file]
        assert anchored, "expected at least one anchored watch"
        for watch in anchored:
            eol_watch.check_anchor(
                watch, (eol_watch.REPO / watch.anchor_file).read_text()
            )
