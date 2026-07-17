# ADR-017: Security Profile Catalog

**Status:** Accepted (extends [ADR-002](002-rule-grounding.md), [ADR-014](014-fix-remediation.md)).
Amended 2026-07-03 — see [§7 Trust model and distribution](#7-trust-model-and-distribution-amendment-2026-07-03), which supersedes the bundled-catalog assumption in §1 and the "ci-smoke = validated" framing in §4–§5.

**Context:** compose-lint's rules are static and image-agnostic. CL-0006 knows a
service should drop capabilities; it cannot know that *this* image (say
`postgres`) needs only `CHOWN, SETGID, SETUID` and nothing else. That
image-specific minimum is not statically derivable — it is a property of what the
container does at runtime, observable only by watching a live container.

Our sibling tool container-sec-derive
(`csd`, not publicly published) derives exactly that: it observes a running container via eBPF and emits a
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
- Follow-ups from §7 (tracked): **#358** (a) decouple the loader from the
  in-package catalog → configured `profiles.path` + (b) reword enrichment as
  attributed/advisory; **#359** (e) per-image test-criteria convention + gate;
  **#360** (c) gate externally-contributed profiles to `exploratory` only + (d)
  the maintainer **derivation automation** —
  a scheduled `derive → validate → update` loop on a BPF-capable host (`csd`'s
  self-hosted runner), seeded from `csd`'s postgres/caddy reference workloads,
  re-deriving on digest bumps, with the representative-workload requirement as an
  explicit precondition. The **#359** criteria gate (implemented) requires each
  `validated` profile to ship a committed criteria doc (scenarios + pass
  criteria) that mirrors its catalog path — `catalog/<rel>.y*ml` ⇒
  `criteria/<rel>.md`, non-empty — so `validate_profiles.py` fails a `validated`
  profile that lacks reviewable criteria (`exploratory` drafts are exempt). In
  `csd`: reconcile the `compose-lint-profile` formatter to this schema (done,
  csd#218).
- Cross-field rules the JSON Schema cannot express (e.g. `status: validated` ⇒
  every dimension's `confidence` ≠ `low` and `validated_via` contains both
  sources) are enforced by the loader/CI, not the schema, and are noted there.

### 8. drop-test as a derivation source (schema 1.1, amendment 2026-07-03)

Runtime observation (the `caps`/`capadd` observers) sees only what a container
exercises **during the observation window**. It is blind to **startup-only**
capabilities — a container that starts as root and drops to an unprivileged user
uses `SETUID`/`SETGID` exactly once, at init, and never again; observation
records them as unused. Acting on that is dangerous: the field case that
motivated this (netdata) observed `SETUID`/`SETGID` as removable, but dropping
them leaves the container **healthy while silently running as root** — a
health-check gate does not catch it.

**drop-test** is the derivation that does: drop a capability, restart the
container, and verify it still behaves *correctly* (not merely "is healthy" —
e.g. that it still dropped to its intended user). (The method is *leave-one-out*
elimination — each candidate is removed individually and the container
re-tested; the name follows `git bisect`'s colloquial "change-and-test to
isolate" sense, not strict binary search.) It covers the full container
lifetime, so it is the authoritative source for `cap_add`, especially startup
caps. Schema 1.1 makes it first-class:

- `derivation.observer: drop-test` marks a dimension derived (or verified) by
  drop-test. A dimension may be observed *and* drop-tested — drop-test is the
  authoritative source, so it takes the `observer` slot.
- `validated_via` gains `drop-test`. A drop-test dimension asserts
  `[drop-test, ci-smoke]` (the drop-and-restart verification plus compose-lint's
  gate) in place of `[bpf-observation, ci-smoke]`.
- **drop-test is kernel-authoritative**, so a drop-test dimension carries
  `confidence: high` (the kernel validated each capability by making the
  container fail or succeed without it). It is exempt from the observation-window
  `duration_seconds ≥ 300` floor — drop-test is not a timed observation.
- **The evidence is mandatory.** A drop-test dimension must carry a
  `derivation.drop_test` block — a non-empty `checks` list of
  `{removed, required, observed}` (which candidate was removed, whether it proved
  required, and the predicate's observed outcome). It cannot merely *claim* the
  source; it must record what was tested and what happened, so the trust-critical
  profiles that override observation are self-justifying. Emitted by csd's
  drop-test producer; enforced for `observer: drop-test` by the loader/CI.

All other `validated` requirements are unchanged (digest-pinned
`validated_image`, committed hash-verified workload — the exerciser used to judge
health during drop-test — `ci-smoke`, and criteria per #359). `1.0` documents
remain valid; `drop-test` is opt-in under `1.1`.

### 9. run_config — the invocation a minimum was derived under (schema 1.2, amendment 2026-07-03)

A derived minimum is a function of **how the container was run**, not just the
image. The same postgres image needs `[DAC_OVERRIDE, SETGID, SETUID]` under the
default (root-then-`gosu`-drop) invocation and **none** of them when run with
`user:` set — the entrypoint sees it is already non-root and skips the privilege
drop. `caddy`'s `/data` is `tmpfs`-droppable for a static file server but a
load-bearing persistent volume for a reverse proxy doing automatic HTTPS. A
profile is only valid for the invocation it was produced under, and nothing in
the schema recorded that invocation.

Schema 1.2 adds an **optional** `derivation.run_config` block capturing it:
`user`, `command`, `entrypoint`, `network`, `pid`, `devices`, `security_opt`,
`mounts`, and `env` (**keys only** — values are never emitted, so a secret cannot
land in committed evidence). It is **emitted by the derivation tool as a
byproduct of the run, not hand-authored** (csd's drop-test producer builds it
from the spec's `run:` block). A consumer applying the profile can diff a target
service against `run_config` and downgrade to a hint when a load-bearing axis
diverges, rather than misapplying a minimum derived under different conditions.

`run_config` is optional and additive: it enlarges no existing constraint, so
all `1.0`/`1.1` documents remain valid. It is descriptive, not causal — it
records the *whole* invocation, not a minimal "which axes matter"; conservative
consumers treat any security-relevant divergence as a warning. Conditions
*outside* the invocation that also bound a minimum — the container runtime's
default cap/seccomp baseline, host LSM enforcement, architecture, fresh-vs-
initialized data state, and above all **workload coverage** (a minimum is only
valid for what the workload exercised) — remain scope stated in each image's
criteria doc (#359), not schema fields.

### 10. app_tier_verified — service-level verification of the whole profile (schema 1.3, amendment 2026-07-04)

A per-dimension `derivation` is backed by a workload that exercises **that one
container**. But many images ship as part of a **multi-container service** (a
database + cache + app tiers), and a minimum that keeps the one container correct
in isolation can still break the *service* when applied. The stronger evidence is
to bring up the whole stack with the hardening applied and confirm the service
does its real job — using the upstream project's own fixtures + API rather than a
hand-rolled probe.

Schema 1.3 adds an **optional top-level** `app_tier_verified` block recording that
verification for the whole profile (not per-dimension, because the stack runs with
every dimension applied at once): `service`, `service_version`, `method`, `check`
(prose), `verified_date`, `result`, and an optional `over_hardening` object
(`applied` + `result`). The `over_hardening` field is what earns the trust — "the
check passed" is weak alone, but "…and a deliberately-too-tight config was shown to
FAIL the same check" proves the gate is not a rubber stamp.

`app_tier_verified` is only meaningful for a cleared profile, so the schema
requires `status: validated` when it is present, and the ci-smoke gate additionally
requires `result: pass`. It is optional and additive — all `1.0`–`1.2` documents
remain valid, and it never substitutes for the per-dimension `validated_via`
evidence (drop-test / bpf-observation / ci-smoke); it is *additional* evidence.
csd's `scripts/apptier_verify.sh` produces it (worked example: immich's postgres
and valkey, verified against immich's released stack and real REST API).

### 11. run_config.sysctls — the kernel posture a posture-dependent minimum assumes (schema 1.4, amendment 2026-07-16)

A capability minimum can be valid **only under a specific kernel sysctl**, and
until 1.4 the schema had nowhere to record it — so the condition lived in prose in
the profile's criteria doc, where a consumer could not act on it.

The canonical case is **NET_BIND_SERVICE**. Whether binding a low port (`:80`,
`:53`) needs a capability is not a property of the image but of
`net.ipv4.ip_unprivileged_port_start` in the container's network namespace:

- **Docker** defaults it to `0` (all ports unprivileged) → the bind needs **no**
  capability, and NET_BIND_SERVICE reads *falsely-removable*.
- The **kernel** default is `1024` → the bind **requires** the capability. Non-Docker
  runtimes and hardened hosts commonly sit here (containerd/CRI-O, and therefore much
  of Kubernetes, typically leave the kernel default unless configured), which is the
  classic "works on my Docker, breaks in k8s" divergence.

So the correct minimum is posture-dependent. csd derives under the **stricter**
posture (pins `net.ipv4.ip_unprivileged_port_start=1024`) — the conservative,
portable answer ("the cap is needed") — and already emits a `sysctls` list in its
`run_config`. Schema 1.4 adds the matching optional
`derivation.run_config.sysctls` field (an array of `"key=value"` strings) so the
profile can state which posture its minimum assumes. A consumer (or compose-lint's
consumer side) then reconciles: on default Docker the profile is *over-permissioned*
for the low-port cap; on a `1024` host it is exactly right and dropping the cap
would break the bind.

The field is optional and additive — all `1.0`–`1.3` documents remain valid, and an
absent/empty `sysctls` means no sysctl was pinned (the minimum holds under Docker's
defaults). It records only what the derivation was pinned under; it does not, by
itself, cause compose-lint to require that posture of a target.

### 12. reference_url — the rendered page behind the hint (schema 1.5, amendment 2026-07-17)

A derived minimum is a function of **(image digest × exact invocation × workload
coverage)**, but an enrichment hint is one line appended to a finding's fix text.
It cannot carry the evidence table, the invocation it was derived under, the
criteria prose, or the re-derive-if conditions — the context a reader needs to
judge whether the minimum applies to *their* service. The honest resolution of
"advisory, not authoritative" is not a smarter hint; it is a **link** to a page
that carries what the hint cannot.

Schema 1.5 adds the optional top-level `reference_url`: an HTTPS URL to the
profile's rendered, human-readable page, set by the **catalog publisher** (the
reference catalog generates one page per profile on GitHub Pages from the same
YAML + criteria doc + manifest — no second source of truth). compose-lint stays
data-free (§7): it never constructs or assumes a URL shape, it only surfaces the
field verbatim on enriched findings' `references` — first, so the text
formatter's single `ref:` line shows the image-specific evidence page rather
than the rule's generic citation. JSON output carries the full list.

The field is optional and additive — all `1.0`–`1.4` documents remain valid, and
a profile without it enriches exactly as before. Because enrichment only ever
consumes *validated* profiles from a catalog the user explicitly configured and
trusts (§7), the URL inherits that trust decision; the https-only pattern is a
floor, not a substitute for it.
