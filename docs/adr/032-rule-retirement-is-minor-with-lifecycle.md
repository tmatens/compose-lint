# ADR-032: Retiring a Refuted Rule Is MINOR, Through the Lifecycle

**Status:** Accepted

**Context:** The draft 1.0 contract made retiring a rule ID a MAJOR. But the
reason a grounded rule leaves the registry post-1.0 is the reason CL-0012,
CL-0015 and CL-0023 left it pre-1.0: evidence refutes its premise, or an
upstream default change makes the flagged configuration a no-op
([ADR-016](016-runtime-rule-premise-validation.md)'s failure modes). A
contract that prices that removal at a 2.0 forces the tool to keep emitting
findings it *knows* describe nothing — the same frozen-error problem
[ADR-031](031-severity-upgrades-are-minor-with-runway.md) fixed for
severities, and worse, because here the signal is not under-priced but false.

Mechanically, retirement is the softest change in the catalogue: findings
stop, so builds only go greener; no pinned setup breaks; machine-output
consumers see an ID stop appearing, which additive-shape parsing already
tolerates. The one sharp edge is configuration: a `.compose-lint.yml` that
references the retired ID. The config layer already warns (not errors) on an
unknown rule id — the message even anticipates "a retired rule" — but under
`--strict-config` (#380) that warning becomes an error, which would break
exactly the pipelines that opted into rigor.

[ADR-030](030-the-policy-is-part-of-the-contract.md)'s asymmetry applies once
more: shipping 1.0 with retirement-as-MINOR keeps the strict option
available as a cheap tightening; the reverse migration would cost a 2.0.

**Decision:** Post-1.0, retiring a rule is a **MINOR**, through the full
deprecation lifecycle, under these conditions:

1. **Evidence, not preference.** Retirement is legal only when the rule's
   premise is refuted by live measurement or an upstream behavior change —
   the ADR-016 bar, recorded in an ADR. "Noisy" is not a retirement reason
   ([ADR-028](028-pre-1.0-rule-id-sweep.md)); prevalence pricing stays out
   of the registry.

   **One narrow exception: a rule admitted on judgment may leave on
   judgment.** [ADR-028](028-pre-1.0-rule-id-sweep.md) records exactly one
   such rule — CL-0014, "the one rule in the set retained on judgment rather
   than on the grounding bar", kept over a pre-1.0 audit's recommendation to
   drop it. Its premise *holds*, so the evidence bar above can never be met;
   what is thin is its grounding, which is a different defect and one the
   evidence bar does not speak to. Without this clause a rule the project
   itself declines to ground is harder to remove than one that is grounded
   and later refuted, which is backwards.

   The exception is deliberately not a general escape hatch. It reaches only
   a rule whose ADR-028 row records it as retained on judgment — a closed
   set, fixed at the 1.0 sweep, currently `{CL-0014}`. A grounded rule still
   needs refutation, so "evidence, not preference" is unchanged for every
   rule that was admitted on evidence. Withdrawal on this ground still needs
   an ADR stating why the judgment changed, and still runs the full
   lifecycle below.

   Included **before** 1.0 because the direction only goes one way:
   admitting this ground later is a loosening and costs a MAJOR, while
   removing it later — deciding judgment is not enough after all — is a
   tightening and costs a MINOR. The same asymmetry the Context above
   applies to retirement itself.
2. **Announce** — `CHANGELOG.md` under `Deprecated` plus a deprecation
   banner on the rule's doc page, in the release that announces it. The
   rule keeps firing through the grace period (its findings are real until
   the removal ships — or, where the refutation shows the findings were
   never real, the announcing release may narrow it to nothing and say so).
3. **Grace** — at least one MINOR between announcement and removal.
4. **Remove** — findings stop; the ID joins the permanently-fallow set
   (never reused, [ADR-005](005-rule-id-scheme.md)); the rule's doc page
   stays as a tombstone stating what refuted it, so `--explain CL-XXXX`
   and existing links keep resolving.
5. **Configs must not break — strict mode included.** Before the first
   post-1.0 retirement, the config layer learns the retired-ID set: a
   config referencing a retired ID warns ("retired in vX.Y, override has
   no effect") but does **not** error under `--strict-config`, which keeps
   meaning "typo or unknown key", not "you once suppressed a rule that
   later died". Strict mode polices mistakes the config author made, not
   history the tool made: an error on the author's typo is the feature,
   an error that arrives because the user upgraded is a contract
   violation dressed as rigor. This is a precondition, not machinery
   built today — no retirement is pending. The fallow pre-1.0 IDs
   (CL-0012, CL-0015, CL-0023) deliberately stay strict *errors* — no
   contract protected 0.x configs — but when the registry is built they
   join it with a distinct message ("reclaimed pre-1.0, refuted premise,
   see the changelog; remove this entry") instead of reading as typos.

**Consequences:**

- `docs/compatibility.md` (rule-ID bullet, lifecycle step 4) and
  `docs/RELEASING.md` (post-1.0 MAJOR list, cheat sheet) are amended
  alongside this ADR; the lifecycle's MAJOR-only removal rule now carries
  two carve-outs (ADR-029 interpreter drops, this one), both
  evidence-or-calendar-gated rather than discretionary.
- Coverage loss is the honest cost: a user relying on a retired rule's
  detection loses it in a MINOR. The lifecycle is the mitigation — the
  deprecation is announced, warned, and graced — and the evidence bar means
  what they lose was, by measurement, not protection.
