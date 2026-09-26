"""The one spelling a report uses for a file (ADR-015, #887).

JSON's ``file`` and SARIF's artifact ``uri`` name the document the evidence is
written in. They had taken whatever spelling the mechanism that found that
document held — the argv spelling for the primary file and an overlay, the lint
host's absolute path for an ``include:`` or cross-file ``extends:`` document,
the path as written for an ``env_file:`` target — so one finding could carry
three forms across two formats, and the ``env_file:`` one named nothing at all
when the run started outside the project directory.

The rule is the one SARIF already applied to most documents: relative to the
working directory, where every tool that follows the path (a log viewer, git,
Code Scanning's ``SRCROOT``) looks it up, with ``/`` separators on every
platform. Joined lexically, like Compose's own path handling, so a symlinked
directory keeps the spelling the user sees rather than its target. A file
outside the working directory has no relative spelling that stays inside it,
so it is reported absolute.
"""

from __future__ import annotations

import os


def report_path(path: str) -> str:
    """``path`` as a report names it: working-directory-relative, or absolute."""
    absolute = os.path.abspath(path)
    try:
        relative = os.path.relpath(absolute, os.getcwd())
    except ValueError:
        # No common base, e.g. another drive on Windows.
        return absolute
    if relative == os.pardir or relative.startswith(os.pardir + os.sep):
        return absolute
    return relative.replace(os.sep, "/")


def is_outside(reported: str) -> bool:
    """Whether a :func:`report_path` result is the absolute fallback."""
    return os.path.isabs(reported)
