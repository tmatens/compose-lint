# ADR-017: Security Profile Catalog

**Status:** Accepted (extends [ADR-002](002-rule-grounding.md), [ADR-014](014-fix-remediation.md))

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

**Consequences:**

- Ships in this PR: the ADR, the JSON Schema, and a pytest guard
  (`tests/test_profile_schema.py`) that checks the schema is a valid Draft 2020-12
  schema and validates the example fixture — matching the existing
  `test_corpus_snapshot_schema.py` pattern (validation via pytest, no new
  workflow, no runtime dep).
- Follow-ups (each its own PR): the ref-normalizing loader + hatch packaging +
  seed profiles derived from `csd`'s postgres/caddy reference workloads; the
  enrichment wiring; the contributor docs + a `profiles/catalog/**` PR-validation
  workflow that appends `ci-smoke`. In `csd`: reconcile the formatter to the
  normalized `image` key, `workload_sha256`, and `observation_backend`.
- Cross-field rules the JSON Schema cannot express (e.g. `status: validated` ⇒
  every dimension's `confidence` ≠ `low` and `validated_via` contains both
  sources) are enforced by the loader/CI, not the schema, and are noted there.
