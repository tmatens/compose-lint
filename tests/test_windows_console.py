"""Color on a classic Windows console: rendered, or plain text — never raw (#1089).

The Win32 calls are injected, so the decision logic runs on every platform.
The one test that needs real kernel32 runs on the os-smoke Windows legs.
"""

from __future__ import annotations

import io
import os
import sys

import pytest

from compose_lint import _windows_console as wc
from compose_lint.formatters import text

VT = wc.ENABLE_VIRTUAL_TERMINAL_PROCESSING


@pytest.fixture(autouse=True)
def _fresh_answers() -> None:
    wc._answers.clear()


def _recording(calls: list[int]) -> wc.SetMode:
    def set_mode(_handle: int, mode: int) -> bool:
        calls.append(mode)
        return True

    return set_mode


def test_a_handle_that_is_not_a_console_does_not_interpret() -> None:
    calls: list[int] = []
    assert not wc.enable_virtual_terminal(7, lambda _h: None, _recording(calls))
    assert calls == []


def test_a_console_already_interpreting_is_left_alone() -> None:
    calls: list[int] = []
    assert wc.enable_virtual_terminal(7, lambda _h: 0x3 | VT, _recording(calls))
    assert calls == []


def test_processing_is_switched_on_keeping_the_other_mode_bits() -> None:
    calls: list[int] = []
    assert wc.enable_virtual_terminal(7, lambda _h: 0x3, _recording(calls))
    assert calls == [0x3 | VT]


def test_a_console_that_refuses_the_flag_does_not_interpret() -> None:
    """Windows 8.1 and Windows 10 before 1511 have no such flag."""
    assert not wc.enable_virtual_terminal(7, lambda _h: 0x3, lambda _h, _m: False)


@pytest.mark.skipif(sys.platform == "win32", reason="the non-Windows path")
def test_off_windows_every_terminal_interprets() -> None:
    assert wc.interprets_ansi(io.StringIO())


class _Console(io.StringIO):
    def __init__(self, fd: int) -> None:
        super().__init__()
        self._fd = fd

    def isatty(self) -> bool:
        return True

    def fileno(self) -> int:
        return self._fd


def _as_windows(monkeypatch: pytest.MonkeyPatch, answer: bool) -> list[int]:
    asked: list[int] = []

    def enable(fd: int) -> bool:
        asked.append(fd)
        return answer

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(wc, "_enable_on_windows", enable)
    return asked


def test_on_windows_the_console_is_asked_once_per_descriptor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked = _as_windows(monkeypatch, True)
    assert wc.interprets_ansi(_Console(1))
    assert wc.interprets_ansi(_Console(1))
    assert wc.interprets_ansi(_Console(2))
    assert asked == [1, 2]


def test_on_windows_a_stream_without_a_descriptor_does_not_interpret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _as_windows(monkeypatch, True)
    assert not wc.interprets_ansi(io.StringIO())


@pytest.fixture
def _no_color_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)


@pytest.mark.usefixtures("_no_color_env")
def test_a_console_that_cannot_interpret_gets_plain_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _as_windows(monkeypatch, False)
    assert text.color_enabled(_Console(1)) is False


@pytest.mark.usefixtures("_no_color_env")
def test_a_console_that_can_interpret_gets_color(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _as_windows(monkeypatch, True)
    assert text.color_enabled(_Console(1)) is True


@pytest.mark.usefixtures("_no_color_env")
def test_force_color_still_forces_and_asks_the_console_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked = _as_windows(monkeypatch, False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert text.color_enabled(_Console(1)) is True
    assert asked == [1]


@pytest.mark.usefixtures("_no_color_env")
def test_a_pipe_never_asks_the_console(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = _as_windows(monkeypatch, True)
    assert text.color_enabled(io.StringIO()) is False
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert text.color_enabled(io.StringIO()) is True
    assert asked == []


@pytest.mark.usefixtures("_no_color_env")
def test_no_color_wins_before_the_console_is_asked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked = _as_windows(monkeypatch, True)
    monkeypatch.setenv("NO_COLOR", "1")
    assert text.color_enabled(_Console(1)) is False
    assert asked == []


@pytest.mark.skipif(sys.platform != "win32", reason="real kernel32 calls")
def test_the_real_win32_path_answers_no_for_a_pipe() -> None:
    """A pipe has no console mode: GetConsoleMode fails, so no color."""
    read_fd, write_fd = os.pipe()
    try:
        assert wc._enable_on_windows(write_fd) is False
    finally:
        os.close(read_fd)
        os.close(write_fd)
