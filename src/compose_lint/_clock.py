"""The one place compose-lint reads the calendar (ADR-041).

A run's result depends on the date only through a suppression's ``expires:``.
Every reader of "today" goes through :func:`utc_today`, so ``--as-of`` and the
tests have a single thing to replace.
"""

from __future__ import annotations

import datetime


def utc_today() -> datetime.date:
    """The UTC date an ``expires:`` is compared with (ADR-041 §3)."""
    return datetime.datetime.now(datetime.UTC).date()
