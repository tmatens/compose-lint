# ADR-017: Security Profile Catalog

**Status:** Accepted (extends [ADR-002](002-rule-grounding.md), [ADR-014](014-fix-remediation.md)).
Amended 2026-07-03 — see [§7 Trust model and distribution](#7-trust-model-and-distribution-amendment-2026-07-03), which supersedes the bundled-catalog assumption in §1 and the "ci-smoke = validated" framing in §4–§5.

**Context:** compose-lint's rules are static and image-agnostic. CL-0006 knows a
service should drop capabilities; it cannot know that *this* image (say
`postgres`) needs only `CHOWN, SETGID, SETUID` and nothing else. That
image-specific minimum is not statically derivable — it is a property of what the
container does at runtime, observable only by watching a live container.

Our sibling tool [container-sec-derive](https://github.com/tmatens/container-sec-derive)
(`csd`) derives exactly that: it observes a running container via eBPF and emits a
minimum-security config (caps, `read_only`/tmpfs, devices, minimized `cap_add`,
privileged decomposition). It already ships a `--format compose-lint-profile`
formatter that emits a per-image YAML entry "for the compose-lint catalog,"
gated behind an acceptance contract (image pinned to a digest, a committed
workload script, ≥5-minute observation window, confidence ≥ moderate, <1% trace
drop-rate). **That catalog never existed on this side.** The producer was written
against a contract the consumer never defined, so the two schemas are unverified
on both ends.

This ADR defines the consumer contract: what a profile document is, where it
lives, how it is matched to a service, and how compose-lint uses it. It is the
foundation the loader (a follow-up PR) and the enrichment wiring (a further
follow-up) build on. It ships the schema and its validation only — no runtime
behavior changes yet.

**Decision:**

### 1. One aggregate document per image

`csd` emits one *fragment* per observer run (a caps run, a separate fs run, …),
each discriminated by `derivation.observer`. A real profile for an image is the
**union** of those fragments across dimensions. The catalog stores that union:
**one document per image**, with an additive per-dimension sub-block under
`dimensions`, each carrying its own `derivation` provenance (dimensions are
derived in separate runs with their own digest, window, and confidence).
Merging fragments into a document is a mechanical collect-under-one-key step,
owned by the contribution flow, not by compose-lint at lint time.

The canonical schema is `src/compose_lint/profiles/schema/profile.schema.json`
(JSON Schema 2020-12), versioned by its own `schema_version` (starts at `"1.0"`),
independent of `csd`'s sidecar `schema_version` (recorded per-dimension under
`derivation.sidecar_schema_version`). compose-lint owns the *catalog schema*;
`csd` owns the *derivation bar*. The two version independently.

### 2. Matching key and staleness

- **`image`** — the canonical repository reference **without** tag or digest
  (`docker.io/library/postgres`, `lscr.io/linuxserver/radarr`), registry and
  namespace normalized. This is the match key. It is deliberately stronger than
  `csd`'s current bare short-name key (`postgres`), which collides across
  registries and loses the namespace; reconciling `csd`'s formatter to emit the
  normalized ref is a required follow-up in that repo.
- **`derivation.validated_image`** — the full `name@sha256:…` actually observed.
  Provenance, not a match key: the exact artifact this dimension was derived from.
- **`applies_to`** (optional) — the staleness policy. Absent ⇒ the profile is
  **advisory across all tags** of that image (enrichment only, never used to
  fail). Present ⇒ the tag globs / digests it is validated for.
- **Match precedence:** exact digest (`applies_to.digests`) → tag-glob
  (`applies_to.tags`) → repository-only (advisory). A conformance/deviation check
  (a rule that *fails* when a service exceeds its profile) is explicitly **out of
  scope here** and deferred to its own ADR; it needs the match/staleness model
  proven in production first.

### 3. Consumption is enrichment-first

A profile **never raises its own finding** under this ADR. When an existing
static rule already fires on a service (CL-0006/0007/0002/0011/0016) and a
`validated` profile matches that service's image, the rule appends the derived
minimum to its `fix` guidance (ADR-014) — e.g. "csd-derived `postgres` profile
needs only `cap_add: [CHOWN, SETGID, SETUID]` (confidence high, digest
`sha256:…`)". This adds precision to guidance we already emit; it changes no rule
semantics, cannot introduce a false positive, and keeps the runtime dependency
surface at PyYAML only. Enrichment ships **off by default** for one release
(gated on `.compose-lint.yml: profiles.enabled`) so the rollout is controlled.

### 4. Provenance is reproducibility, including the gadget transition

Every dimension records how it was derived: `tool`, `tool_version`,
`sidecar_schema_version`, `observer`, `validated_image`, `validated_date`,
`duration_seconds`, `confidence`, `workload` (repo-relative path to the committed
exerciser) and `workload_sha256` (so the entry is reproducible and tamper-evident),
and `validated_via` (`csd` emits `[bpf-observation]`; compose-lint CI appends
`ci-smoke` after its own gate — both are required for `status: validated`).

`csd` is migrating some observation from built-in Inspektor Gadget gadgets to
**csd-authored gadgets**. A profile derived with a custom gadget is only
reproducible if the gadget's image and digest are recorded — the upstream `ig`
version alone no longer pins the observation. `derivation.observation_backend`
therefore carries `ig_version` plus an optional `gadgets: [{name, image, digest}]`
list. This is designed in now so custom-gadget provenance is not a retrofit.

### 5. Validated vs. exploratory

`status: validated` means the dimension cleared `csd`'s acceptance contract **and**
compose-lint's `ci-smoke` gate. `status: exploratory` mirrors `csd`'s
`--allow-exploratory`: a below-bar draft that carries a non-empty
`acceptance_contract_violations` list, lives under `profiles/catalog/exploratory/`,
and is **never** used for enrichment or (future) conformance — advisory review
material only. The schema enforces the status/violations coupling with a
conditional.

### 7. Trust model and distribution (amendment 2026-07-03)

Sections 1–6 defined the profile *format* and *consumption*. They left a hole:
they conflated the `profile-validate` gate ("ci-smoke") with verification, and
assumed the catalog ships inside the compose-lint package. Both are wrong for a
public tool. This section is the correction.

**Integrity is not authenticity.** The gate verifies that a profile is
*well-formed* — schema-valid, digest-pinned, its `workload_sha256` matches the
committed script, its confidence/duration meet the bar. Every one of those fields
is **self-asserted by whoever wrote the file.** The gate never re-runs `csd`,
never confirms the observation happened, and cannot tell whether the workload was
*representative*. So `validated_via: [ci-smoke]` means "passed compose-lint's
structural validation," **not** "compose-lint reproduced this." A profile from an
untrusted source is therefore **not endorsable on the strength of the gate alone.**

**Endorsement rests on maintainer-owned reproducible automation, not third-party
claims.** compose-lint endorses (enriches from) only profiles that its own
automation derived and can re-derive — turning "trust a stranger's YAML" into
"trust a CI job we own." Consequences:

- **Externally contributed profiles land `exploratory` only** (never enrich, never
  fail a lint) until the maintainer automation can reproduce them. Reproduction
  promotes them to `validated`; nothing else does.
- **Representative-workload requirement (hard gate).** A profile is promotable to
  `validated`/endorsed only when produced by automation whose workload
  **represents real use of the service(s)** — not a token liveness poke. An
  observation-derived profile is only as good as what the workload exercised; a
  thin workload yields a confident-looking but under-scoped profile that
  reproduces perfectly while being wrong. So the bar is **reproducible + current +
  representative**, and representativeness is a per-service human judgment that
  does **not** scale. The endorsed set is therefore deliberately **small**, and
  grows only as the derivation automation matures — never by accepting unverified
  submissions.
- **Transparent, reviewable test criteria (per image).** Because
  representativeness is a human judgment, the material behind it must be open to
  audit: every endorsed image ships its derivation criteria *alongside the
  profile* — the committed workload script (already hash-pinned via
  `workload_sha256`) **and** a human-readable statement of the real-use scenarios
  it exercises and the pass/representativeness criteria used to accept it.
  Endorsement is only as credible as a reviewer's ability to inspect *how* the
  profile was derived; a profile whose criteria are not published cannot be
  `validated`. This makes "trust the automation" auditable rather than a bare
  assertion, and is enforced by the gate (a profile must reference committed,
  reviewable criteria).

**Distribution: compose-lint core ships no catalog data.** Bundling the catalog in
the wheel (the §1 assumption) is reversed: it grows the package unboundedly,
couples profile updates to linter releases, and makes shipping equal endorsing.
Instead the linter ships only the *machinery* (schema, loader, validator,
enrichment) and reads profiles from a source the user configures
(`profiles.path`, default none). The endorsed catalog is a **separate,
independently-versioned artifact** (its own repo/package) that the maintainer
automation owns and updates; users opt into it explicitly, and can point at their
own instead. This bounds the linter, decouples profile cadence, and scopes
endorsement to a source the user consciously trusts.

**Enrichment wording is attributed, not asserted.** Guidance names its source and
its unverified-for-you nature (e.g. "derived by \<source\>, confidence X, digest
Y — not independently verified here") rather than stating the minimum as
compose-lint fact.

**Consequences:**

- Ships in this PR: the ADR, the JSON Schema, and a pytest guard
  (`tests/test_profile_schema.py`) that checks the schema is a valid Draft 2020-12
  schema and validates the example fixture — matching the existing
  `test_corpus_snapshot_schema.py` pattern (validation via pytest, no new
  workflow, no runtime dep).
- Landed (PRs #353–#356): the JSON Schema + validation, the ref-normalizing
  loader + packaging, opt-in enrichment, and the `profile-validate` (`validate_profiles.py`)
  gate + contributor guide.
- Superseded by §7: the **bundled catalog** from the loader/packaging PR. The
  loader must instead read from a configured external `profiles.path` (default
  none); the empty in-package catalog is removed. (Follow-up.)
- Follow-ups from §7 (each its own PR/issue): (a) decouple the loader from the
  in-package catalog → configured `profiles.path`; (b) reword enrichment as
  attributed/advisory (§7); (c) gate externally-contributed profiles to
  `exploratory` only; (d) stand up the maintainer **derivation automation** —
  a scheduled `derive → validate → update` loop on a BPF-capable host (`csd`'s
  self-hosted runner), seeded from `csd`'s postgres/caddy reference workloads,
  re-deriving on digest bumps, with the representative-workload requirement as an
  explicit precondition; (e) per-image **test-criteria convention + gate** — each
  profile references a committed criteria doc (scenarios + pass criteria) beside
  its workload, and `validate_profiles.py` fails a `validated` profile that lacks
  reviewable criteria. In `csd`: reconcile the `compose-lint-profile` formatter
  to this schema (tracked in csd issue #218).
- Cross-field rules the JSON Schema cannot express (e.g. `status: validated` ⇒
  every dimension's `confidence` ≠ `low` and `validated_via` contains both
  sources) are enforced by the loader/CI, not the schema, and are noted there.
