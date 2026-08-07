# ADR-019: Withdraw the security profile catalog

**Status:** Accepted (supersedes [ADR-017](017-security-profile-catalog.md) and
[ADR-018](018-confidence-as-multi-axis.md)).

**Context:** [ADR-017](017-security-profile-catalog.md) introduced profile
enrichment: compose-lint would match a service's `image:` against a catalog of
csd-derived security profiles and append an image-specific `profile hint` to a
finding's `fix` text — the observed-minimum `cap_add` for `postgres`, say,
instead of a generic `<SPECIFIC_CAP>` placeholder. It shipped as an opt-in
experimental preview: `profiles.enabled` off by default, no bundled catalog
(§7), and a stderr notice whenever enrichment was active.

The consumption machinery landed in full — loader, schema, reference resolver,
`enrich_fix`, a validator script, and a `profile-validate` CI gate, roughly
600 lines of implementation against 950 lines of tests. What never landed was
the other half: [#360](https://github.com/tmatens/compose-lint/issues/360), the
derive → validate → publish automation that §7 makes a precondition for
endorsing any profile as `validated`. That epic depends on csd emitting the
catalog schema and on access to a BPF-capable runner, neither of which
materialised.

So compose-lint carried a fully built consumer of a catalog that does not
exist, gated behind a flag whose only honest setting was off.

**Decision:** Withdraw the feature. Remove the `profiles` package, the
validator, the `profile-validate` CI gate, the `profiles` config block, and the
`profile_lookup` engine parameter. compose-lint does not consume a security
profile catalog, and does not ship per-image capability data.

**Rationale:**

1. **The trust precondition was never met.** ADR-017 §7 is explicit that
   compose-lint endorses only profiles its own automation can re-derive. Absent
   that automation, every hint the pipeline could emit came from a catalog
   nobody had independently reproduced — exactly the "hand-authored security
   spec" failure mode §7 exists to prevent.
2. **Static analysis cannot validate a runtime claim.** compose-lint reads
   YAML. A derived minimum is valid only for the precise invocation it was
   produced under (digest, `user:`, `command:`, mounts). The preview's own
   stderr notice conceded this — it told users the hint was advisory, unverified
   and possibly wrong for their deployment. Guidance that ships with that
   caveat attached is weak guidance.
3. **Dead weight has a cost.** ~2,200 lines across source, tests and docs, plus
   a CI job and two ADRs reading as Accepted, all of which anyone touching
   `engine.py` or `config.py` had to reason about.

**Consequences:**

- **`profiles:` in a `.compose-lint.yml` is now an unrecognized top-level key.**
  It takes the standard warn-and-continue path — a stderr warning, exit code
  unchanged — so an ordinary run does not break. Under `--strict-config` it is
  a hard error (exit 2), like any other unrecognized key.
- **[#4](https://github.com/tmatens/compose-lint/issues/4)** (make CL-0006's
  `<SPECIFIC_CAP>` actionable) reopens as the original need. The remaining path
  is to teach users how to *determine* an image's required set — `docker diff`,
  the `capable` BPF tool, the "entrypoint switches users ⇒ likely SETUID +
  SETGID" heuristic — rather than to ship a per-image answer.
- **[#360](https://github.com/tmatens/compose-lint/issues/360)** is closed as
  won't-do.
- **csd's `internal/parity` gate** pins compose-lint's curated capability set by
  value in its own `testdata/`, so it does not break; but its premise — that the
  two sides must not drift — no longer has a compose-lint side. Reconciling it
  is csd's call and is out of scope here.
- Reversal is a `git revert` away if the derivation automation is ever built.

**Alternatives considered:**

- *Deprecate now, remove later.* Rejected: the feature is already off by default
  and self-described as experimental, so a deprecation window protects nobody.
  It would defer identical work while keeping the maintenance and comprehension
  cost.
- *Keep the consumer, wait for the catalog.* Rejected: #360's blockers are
  external (csd schema support, BPF runner access) with no timeline, and csd
  itself is under a maintenance freeze.
- *Delete ADR-017/018 outright.* Rejected: ADRs are decision records, not
  documentation of current state. Deleting them erases why the catalog was
  attempted, which is the most useful thing to know before attempting it again.
