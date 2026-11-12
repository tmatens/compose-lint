"""Session-wide test configuration.

Two jobs: say which Compose answered, and start each test with no `.env` values
to quote (see the fixture below).

Six suites derive this project's loader semantics from ``docker compose`` on
every run, and until now nothing in the output recorded which binary they
asked. That is not a cosmetic gap. The `ubuntu-24.04` runner image pins its
own Compose plugin — `toolset-2404.json` holds it at 2.38.2 while docker/compose
is on 5.x — so CI was grading `include:` orderings measured on 5.5.0 against a
binary that *refuses* the documents describing them
(`services.web conflicts with imported resource`), and a reader of the run had
no way to tell.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from compose_lint import _env_quote
from tests.oracle_harness import oracle_version

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _forget_env_values() -> Iterator[None]:
    """Start and end every test with no ``.env`` values to quote.

    The parser records each value it substitutes process-wide so the output
    sinks can quote it back (``_env_quote``). A value one test's fixture
    substituted must not rewrite another test's expected text.
    """
    _env_quote.forget()
    yield
    _env_quote.forget()


def pytest_report_header() -> str:
    """Name the oracle in the pytest header, or say there is not one."""
    version = oracle_version()
    if version is None:
        return "docker compose: unavailable (differential suites skip)"
    return f"docker compose: {version}"
