"""Session-wide test configuration.

One job: say which Compose answered.

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

from tests.oracle_harness import oracle_version


def pytest_report_header() -> str:
    """Name the oracle in the pytest header, or say there is not one."""
    version = oracle_version()
    if version is None:
        return "docker compose: unavailable (differential suites skip)"
    return f"docker compose: {version}"
