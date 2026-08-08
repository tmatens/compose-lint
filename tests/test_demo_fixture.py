"""Guard the README demo fixtures against silent drift (#404).

Two GIFs are recorded from fixtures in ``scripts/demo/``, and what each one
shows is described in three more places: the demo README, the tape's comments,
and the main README's alt text. Nothing else re-runs those fixtures, so a rule
change (new rule firing, severity reclassification, a fixer gaining or losing
an edit) or a fixture edit can silently invalidate all of them — exactly what
happened when the fixture swap in #404 left the GIF and its descriptions
showing findings that no longer fire.

These tests pin what each cast shows. When one fails, that demo's story has
changed: re-render the GIF and update the descriptions (see
``scripts/demo/README.md``), then update the expectation here.
"""

from __future__ import annotations

from pathlib import Path

from compose_lint.engine import run_rules
from compose_lint.fix import apply_edits, collect_edits
from compose_lint.models import Severity
from compose_lint.parser import load_compose

DEMO_DIR = Path(__file__).parent.parent / "scripts" / "demo"
HERO_FIXTURE = DEMO_DIR / "docker-compose.yml"
FIX_FIXTURE = DEMO_DIR / "fix-compose.yml"

# What the hero GIF (demo.tape) and its descriptions show, severity-sorted as in
# the text report: CRITICAL socket mount leading, then the sensitive host mount,
# then the tag-only image pin. The demo also runs `--explain CL-0001`, so the
# leading finding's rule id is baked into the tape as well.
HERO_EXPECTED = {
    ("CL-0001", Severity.CRITICAL),
    ("CL-0013", Severity.HIGH),
    ("CL-0019", Severity.MEDIUM),
}

# What the fix GIF (fix.tape) shows. Its whole narrative is the split between
# these two sets: three findings `fix` remediates automatically, and one it
# refuses because no safe automatic fix exists. The tape's on-screen summary
# lines ("3 fix(es) available; 1 finding(s) need manual review") quote these
# counts, and its second screen depends on the leftover being below the default
# HIGH threshold so the re-lint verdict flips FAIL -> PASS.
FIX_AUTOFIXED = {"CL-0003", "CL-0005", "CL-0007"}
FIX_MANUAL = {"CL-0019"}


def test_hero_fixture_findings_match_the_recorded_gif() -> None:
    data, lines = load_compose(HERO_FIXTURE)
    findings = run_rules(data, lines)
    assert {(f.rule_id, f.severity) for f in findings} == HERO_EXPECTED, (
        "The hero demo fixture's findings no longer match what the README GIF "
        "shows. Re-render the demo and update its descriptions (see "
        "scripts/demo/README.md), then update HERO_EXPECTED here."
    )


def test_fix_fixture_splits_as_the_recorded_gif_shows() -> None:
    data, lines = load_compose(FIX_FIXTURE)
    text = FIX_FIXTURE.read_text(encoding="utf-8")
    result = collect_edits(run_rules(data, lines), data, lines, text)
    assert {f.rule_id for f in result.fixed} == FIX_AUTOFIXED
    assert {f.rule_id for f in result.manual} == FIX_MANUAL
    assert len(result.edits) == 3, (
        "The fix demo's summary line quotes the edit count; re-render "
        "docs/assets/demo-fix.gif and update this expectation."
    )


def test_fix_fixture_verdict_flips_to_pass_once_fixed() -> None:
    """The fix GIF's payoff: FAIL before, PASS at the default threshold after."""
    data, lines = load_compose(FIX_FIXTURE)
    text = FIX_FIXTURE.read_text(encoding="utf-8")
    before = run_rules(data, lines)
    assert any(f.severity >= Severity.HIGH for f in before), (
        "The fix demo opens on a FAIL verdict, which needs a finding at or "
        "above the default HIGH threshold."
    )

    result = collect_edits(before, data, lines, text)
    patched = apply_edits(text, result.edits)
    patched_path = FIX_FIXTURE.parent / "_patched.yml"
    try:
        patched_path.write_text(patched, encoding="utf-8")
        after = run_rules(*load_compose(patched_path))
    finally:
        patched_path.unlink(missing_ok=True)
    assert not any(f.severity >= Severity.HIGH for f in after), (
        "The fix demo's second screen shows PASS after --apply; the fixed "
        "file now retains a finding at or above HIGH."
    )
