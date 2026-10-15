"""Let a classic Windows console show compose-lint's colors (#1089).

Color is ANSI escape sequences. Windows Terminal interprets them by default;
the classic console host (conhost — the cmd.exe and PowerShell window that is
the default on Windows 10 and Server) interprets them only once the program
sets ``ENABLE_VIRTUAL_TERMINAL_PROCESSING`` on the console handle. Without it
every colored line prints its sequences literally: ``←[31mCRITICAL←[0m``.

So before coloring a console stream on Windows, ask the console to interpret
sequences. Where it cannot — Windows 8.1 and Windows 10 before 1511 lack the
flag, and a handle that is not a console (the ``NUL`` device answers
``isatty()`` too) has no mode at all — the answer is no, and the caller prints
plain text. Every outcome is color or plain text, never raw sequences.

Setting the flag is Microsoft's documented route, and a no-op where it is
already on: Windows Terminal, VS Code's terminal and mintty interpret
sequences either way. The mode is left set when the process exits, as Python
itself leaves it. Nothing here runs off Windows.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import TextIO

# From wincon.h.
ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

# One answer per file descriptor: the console mode does not change under us,
# and color_enabled() is asked once per colored fragment.
_answers: dict[int, bool] = {}

GetMode = Callable[[int], "int | None"]
SetMode = Callable[[int, int], bool]


def interprets_ansi(stream: TextIO) -> bool:
    """Whether ANSI sequences written to ``stream`` will render as color.

    Always True off Windows. On Windows, True when ``stream``'s console
    interprets sequences, turning that on if it is off and can be.
    """
    if sys.platform != "win32":
        return True
    try:
        fd = stream.fileno()
    except (AttributeError, OSError, ValueError):
        return False
    if fd not in _answers:
        _answers[fd] = _enable_on_windows(fd)
    return _answers[fd]


def enable_virtual_terminal(handle: int, get_mode: GetMode, set_mode: SetMode) -> bool:
    """Turn on sequence processing for ``handle``; say whether it is on.

    ``get_mode`` returns the console mode, or None when ``handle`` is not a
    console. Separated from the Win32 calls so it is tested on every platform.
    """
    mode = get_mode(handle)
    if mode is None:
        return False
    if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
        return True
    return set_mode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)


def _enable_on_windows(fd: int) -> bool:  # pragma: no cover - Win32 calls only
    """Wire :func:`enable_virtual_terminal` to kernel32 for ``fd``.

    Not reachable off Windows; the decision logic it delegates to is tested on
    every platform, and the os-smoke Windows legs import and run this path.
    """
    if sys.platform != "win32":
        return True
    import ctypes.wintypes
    import msvcrt

    wintypes = ctypes.wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetConsoleMode.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
    kernel32.GetConsoleMode.restype = wintypes.BOOL
    kernel32.SetConsoleMode.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.SetConsoleMode.restype = wintypes.BOOL

    def get_mode(handle: int) -> int | None:
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return None
        return int(mode.value)

    def set_mode(handle: int, mode: int) -> bool:
        return bool(kernel32.SetConsoleMode(handle, mode))

    try:
        handle = msvcrt.get_osfhandle(fd)
    except OSError:
        return False
    return enable_virtual_terminal(handle, get_mode, set_mode)
