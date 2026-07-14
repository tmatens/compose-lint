"""Guard the README demo fixture against silent drift (#404).

The README hero GIF is recorded from ``scripts/demo/docker-compose.yml``, and
the findings it shows are described in three more places: the demo README, the
tape's comments, and the main README's alt text. Nothing else re-runs the
fixture, so a rule change (new rule firing, severity reclassification) or a
fixture edit can silently invalidate all of them — exactly what happened when
the fixture swap in #404 left the GIF and its descriptions showing findings
that no longer fire.

This test pins the fixture's finding set. When it fails, the demo's story has
changed: re-render the GIF and update the descriptions (see
``scripts/demo/README.md``), then update the expectation here.
"""

from __future__ import annotations

from pathlib import Path

from compose_lint.engine import run_rules
from compose_lint.models import Severity
from compose_lint.parser import load_compose

DEMO_FIXTURE = Path(__file__).parent.parent / "scripts" / "demo" / "docker-compose.yml"

# What the recorded GIF and its descriptions show, severity-sorted as in the
# text report: CRITICAL socket mount leading, then the sensitive host mount,
# then the tag-only image pin. The demo also runs `--explain CL-0001`, so the
# leading finding's rule id is baked into the tape as well.
EXPECTED = {
    ("CL-0001", Severity.CRITICAL),
    ("CL-0013", Severity.HIGH),
    ("CL-0019", Severity.MEDIUM),
}


def test_demo_fixture_findings_match_the_recorded_gif() -> None:
    data, lines = load_compose(DEMO_FIXTURE)
    findings = run_rules(data, lines)
    assert {(f.rule_id, f.severity) for f in findings} == EXPECTED, (
        "The demo fixture's findings no longer match what the README GIF "
        "shows. Re-render the demo and update its descriptions (see "
        "scripts/demo/README.md), then update EXPECTED here."
    )
