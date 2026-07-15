# Contributing a security profile

compose-lint can enrich its fix guidance with **derived security profiles**: the
observed minimum capabilities, filesystem, devices, and privilege a specific
image actually needs. Profiles are produced by container-sec-derive (`csd`), a
runtime derivation tool (drop-test + live eBPF observation; not yet published),
and live in the external
[container-security-profiles](https://github.com/tmatens/container-security-profiles)
catalog — profile contributions go there, not to this repository. See
[ADR-017](adr/017-security-profile-catalog.md) for the model and
[configuration.md](configuration.md#profile-enrichment) for how users opt in.

Profiles are **derived, never hand-authored.** A guessed cap list is exactly the
mistake compose-lint exists to catch; the value of a profile is that its numbers
came from real observation and are reproducible.

> **Trust model (ADR-017 §7, 2026-07-03).** The `profile-validate` gate checks a
> profile is *well-formed* — it does **not** re-run `csd` or confirm the
> observation happened or was representative. So compose-lint **endorses only
> profiles its own maintainer automation derived and can re-derive.** A profile
> you contribute is accepted as **`exploratory` only** (advisory, never used to
> enrich) until that automation reproduces it. Promotion additionally requires
> the run's **workload to represent real use of the service** — a token liveness
> poke under-scopes the profile. Each image's **test criteria are public and
> reviewable** — the committed workload script plus a statement of the real-use
> scenarios it exercises — so anyone can audit *how* a profile was derived; a
> profile without published criteria cannot be `validated`. The endorsed catalog
> is a small, external,
> automation-maintained artifact the user opts into (`profiles.path`), **not**
> data bundled in the linter. Both halves are live: the loader shipped in
> 0.13.0, and the catalog is public at
> [container-security-profiles](https://github.com/tmatens/container-security-profiles)
> with scheduled re-derivation automation. The rest of this guide describes the
> derivation mechanics, which are unchanged.

## What a profile is

One YAML document per image, conforming to
[`profile.schema.json`](../src/compose_lint/profiles/schema/profile.schema.json).
It carries one additive block per security dimension, each with its own
`derivation` provenance, because `csd` observes each dimension in a separate run:

| Dimension | Rule it informs | csd observer |
|---|---|---|
| `capabilities` | CL-0006 | `caps` |
| `filesystem` | CL-0007 | `fs` |
| `devices` | CL-0016 | `devices` |
| `cap_add_validation` | CL-0011 | `capadd` |
| `privileged_decomposition` | CL-0002 | `privileged` |

A profile is the **union** of these across separate `csd` runs, collected under
one `image` key.

## Deriving a profile

Run `csd` against a live, **digest-pinned** container, driven by a workload
script that exercises the paths you care about, for at least five minutes:

```bash
csd --image docker.io/library/postgres@sha256:<digest> \
    --observe caps \
    --duration 600s \
    --workload profiles/workloads/postgres.sh \
    --format compose-lint-profile > entry.yml
```

Repeat per dimension (`--observe fs`, `--observe devices`, …) and merge the
fragments into one document keyed by the image.

### The acceptance contract (validated profiles)

`csd`'s formatter refuses to emit a `validated` entry unless every term holds;
the catalog's CI re-checks them with this repo's validator:

- image pinned to a `@sha256:` digest (`derivation.validated_image`), and only
  **immutable version tags** in `applies_to.tags`;
- a committed workload script, hash-matched by `workload_sha256`;
- evidence matching the derivation method: **drop-test** (remove each granted
  element in turn, restart, re-verify the workload) requires the per-element
  `drop_test.checks` block; **bpf-observation** requires
  `duration_seconds >= 300` per dimension;
- `confidence` is `high` or `moderate`;
- clean observation (no coverage warnings, drop-rate < 1%, no replica
  disagreement).

A run below the bar emits under an `exploratory:` block instead
(`csd … --allow-exploratory`). Contribute those under `catalog/exploratory/`;
they are review material and are never used to enrich (or fail) a lint.

## Where files go

Profiles live in the external
[container-security-profiles](https://github.com/tmatens/container-security-profiles)
repository (not here — compose-lint ships no catalog):

```
catalog/<registry>/<org>/<image>.yaml               # validated
catalog/exploratory/<registry>/<org>/<image>.yaml   # below-bar / awaiting reproduction
criteria/<registry>/<org>/<image>.md                # public, reviewable test criteria
profiles/workloads/<name>.sh                        # committed exerciser
```

The loader indexes each document by its own `image` field, not by path.
Workload scripts are audit artifacts referenced by the repo-relative
`derivation.workload` path. See that repository's `CONTRIBUTING.md` for the PR
checklist.

## `validated_via` and the ci-smoke gate

`csd` will not claim a check it did not run (`validated_via` lists only what
happened). The catalog repo's CI is the second source: it fetches this repo's
schema and validator at a pinned commit (`contract/compose-lint.ref` there) and
runs it on every change, so a `validated` profile reads e.g.
`validated_via: [drop-test, ci-smoke]`. The gate fails a PR that claims
`ci-smoke` without being a well-formed, digest-pinned, workload-verified
artifact — the claim is only ever as good as the check backing it.

The validator lives here and can be run against any catalog checkout:

```bash
python scripts/validate_profiles.py
```

It validates every catalog document against the schema, enforces the
validated/exploratory invariants the schema cannot express, and verifies each
`workload_sha256` against the committed script.
