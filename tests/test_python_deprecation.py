"""Tests for the end-of-life warning on the interpreter about to be dropped.

Deleted wholesale when the floor moves — the warning it covers is meant to be
temporary, and a test that outlives its subject becomes an argument for keeping
the code.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from compose_lint import __version__
from compose_lint.cli import _NEXT_PYTHON_FLOOR, _warn_deprecated_python

if TYPE_CHECKING:
    import pytest

BELOW_FLOOR = (3, 10, 14)
AT_FLOOR = (*_NEXT_PYTHON_FLOOR, 0)


class TestDeprecatedPythonWarning:
    """The last release supporting an interpreter has to say so."""

    def test_warns_below_the_floor(self, capsys: pytest.CaptureFixture[str]) -> None:
        _warn_deprecated_python(BELOW_FLOOR)
        assert "warning:" in capsys.readouterr().err

    def test_silent_at_and_above_the_floor(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _warn_deprecated_python(AT_FLOOR)
        _warn_deprecated_python((99, 0, 0))
        captured = capsys.readouterr()
        assert captured.err == ""
        assert captured.out == ""

    def test_never_writes_to_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        """A JSON or SARIF consumer parses stdout; the warning must not reach it."""
        _warn_deprecated_python(BELOW_FLOOR)
        assert capsys.readouterr().out == ""

    def test_names_the_running_interpreter_exactly(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Down to the patch level, so the user need not go looking for it."""
        _warn_deprecated_python(BELOW_FLOOR)
        assert "Python 3.10.14" in capsys.readouterr().err

    def test_pin_advice_is_the_installed_version(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Whatever the user is holding is what they are told to pin.

        A literal here would send everyone to one release regardless of what
        they had, which is worse advice than none: it is the version *they* are
        on that still supports their interpreter.
        """
        _warn_deprecated_python(BELOW_FLOOR)
        assert f"compose-lint=={__version__}" in capsys.readouterr().err

    def test_names_no_release_as_the_one_that_drops_support(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The dropping release is not chosen yet, so the message anchors
        on upstream EOL and the 1.0 milestone instead.

        Guards the acceptance criterion directly: the only ``0.x``-shaped token
        allowed in the message is the installed version in the pin advice.
        """
        _warn_deprecated_python(BELOW_FLOOR)
        message = capsys.readouterr().err.replace(f"compose-lint=={__version__}", "")
        assert re.search(r"\b0\.\d+", message) is None
        assert "end-of-life in October 2026" in message
        assert "before its 1.0 release" in message

    def test_points_at_the_replacement(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _warn_deprecated_python(BELOW_FLOOR)
        floor = f"{_NEXT_PYTHON_FLOOR[0]}.{_NEXT_PYTHON_FLOOR[1]}"
        assert f"Upgrade to {floor}+" in capsys.readouterr().err
