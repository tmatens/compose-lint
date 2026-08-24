# ADR-031: Severity Upgrades Are MINOR, With a One-Release Runway

**Status:** Accepted

**Context:** The draft 1.0 contract made a severity *upgrade* a MAJOR, on the
argument that `LOW → HIGH` can newly fail a threshold-gated CI run. Examined
against the rest of the contract, that protection was incoherent: a brand-new
HIGH rule fails the same pipeline the same way, and "new findings are not a
breaking change" blesses it as MINOR. The MAJOR classification guarded a door
the contract holds open elsewhere — while freezing errors in the risk signal,
which for a security linter is the wrong thing to protect. If live evidence
shows a rule under-graded (a new exploitation technique, a corrected axis —
exactly what the premise methodology exists to surface), the tool must be able
to say so without a 2.0.

[ADR-030](030-the-policy-is-part-of-the-contract.md) sharpens the stakes into
an asymmetry: tightening the contract later is a MINOR; loosening it later is
a MAJOR. Shipping 1.0 with upgrades-as-MAJOR is therefore the irreversible
choice — relaxing it on first contact with reality would cost a 2.0 — while
shipping upgrades-as-MINOR keeps the strict option open forever.

**Decision:** Post-1.0, a severity upgrade is a **MINOR with a one-release
runway**:

1. **Announce** — the release *before* the move states it in `CHANGELOG.md`
   under `Changed`: the rule, both tiers, and the release class that will
   apply it ("in the next MINOR").
2. **Apply** — the next MINOR ships the new severity, with its own `Changed`
   entry linking the derivation.
3. **Derive** — the upgrade is legal only when the two-axis model produces
   the new number (an axis correction, new live evidence, or a declared
   override from the closed reason list). Severity never moves on judgment
   alone; the derivation gate is what makes the smaller bump honest.

Downgrades remain plain MINOR, no runway — they can only turn a red build
green. Where only a *subset* of a rule's matches deserves the higher tier,
the split pattern (ADR-028: new ID for the dangerous subset) remains
preferred over upgrading the whole rule, because it also keeps existing
suppressions from silently covering the more dangerous rule.

**Deliberately provisional in one direction:** this is the watch-and-see
position. If observation shows runway upgrades burning users in practice,
tightening to upgrades-as-MAJOR is a MINOR contract change under ADR-030.
The reverse migration would have cost a 2.0 — that asymmetry, not certainty
about the right answer, is why 1.0 ships with this rule.

**Consequences:**

- `docs/compatibility.md` (severity paragraph) and `docs/RELEASING.md`
  (post-1.0 MINOR/MAJOR lists, cheat sheet) are amended alongside this ADR;
  the severity-upgrade bullet leaves the MAJOR list.
- A threshold-gated (`--fail-on`) user sees an upgrade coming one full
  release ahead; a pinned user is untouched at every step; per-rule
  disables and suppressions keep working across the move.
- The maintainer carries one piece of cross-release state per upgrade (the
  pending announcement). No machinery enforces the runway yet; if a pending
  move is ever forgotten, the release checklist in RELEASING.md is the
  backstop, and automating it is worth revisiting on the first miss.
