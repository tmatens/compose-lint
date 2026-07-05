"""Fixture-scenario coverage guard (#379).

Rule tests load multi-service YAML fixtures and assert findings service by
service (``data["services"]["<name>"]``). Nothing otherwise forces a matching
assertion when a new service variant is added to a fixture, so a coverage gap
can open silently — a hardened or malformed variant ships untested.

This meta-test walks every fixture that has a real ``services:`` mapping and
requires each service name to appear (quoted) somewhere in the test sources. It
is a tripwire, not a proof: a service whose name is a common word could be
matched incidentally, and whole-file CLI fixtures are covered by name where a
per-service unit test references them. But a uniquely-named new variant with no
test at all — the case this guards — trips it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from compose_lint.parser import ComposeError, load_compose

TESTS_DIR = Path(__file__).parent
FIXTURES_DIR = TESTS_DIR / "compose_files"


def _fixture_services() -> list[tuple[str, str]]:
    """Return (fixture_name, service_name) for every service in a fixture that
    parses to a real services mapping. Fragments, v1, and invalid fixtures (no
    services mapping) have no per-service scenario to assert and are skipped."""
    out: list[tuple[str, str]] = []
    for fixture in sorted(FIXTURES_DIR.glob("*.yml")):
        try:
            data, _lines = load_compose(fixture)
        except (ComposeError, OSError):
            continue
        services = data.get("services") if isinstance(data, dict) else None
        if not isinstance(services, dict):
            continue
        out.extend((fixture.name, str(service)) for service in services)
    return out


# Concatenated test sources (excluding this file, which names services only in
# prose) — the corpus a service must appear in to count as referenced.
_TEST_SOURCES = "\n".join(
    p.read_text(encoding="utf-8")
    for p in sorted(TESTS_DIR.glob("test_*.py"))
    if p.name != Path(__file__).name
)


@pytest.mark.parametrize(
    ("fixture", "service"),
    _fixture_services(),
    ids=lambda v: v if isinstance(v, str) else str(v),
)
def test_every_fixture_service_is_referenced(fixture: str, service: str) -> None:
    referenced = f'"{service}"' in _TEST_SOURCES or f"'{service}'" in _TEST_SOURCES
    assert referenced, (
        f"service '{service}' in tests/compose_files/{fixture} is not referenced "
        f"by any test — add a case asserting its expected findings (or remove it "
        f"from the fixture)."
    )


def test_guard_actually_scans_something() -> None:
    # Defend the guard itself: if the fixture glob or parser silently found no
    # services, the parametrized test would vacuously pass.
    assert len(_fixture_services()) > 20
