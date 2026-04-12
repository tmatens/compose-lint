# Distribution channels

This document defines the contract every distribution channel must follow.
When a new channel is added (VS Code extension, npm package, etc.), it plugs
into this pattern rather than getting its own ad-hoc workflow.

## Principles

### 1. One tag, all artifacts

A `vX.Y.Z` tag is the single release event. Every channel derives its version
from that tag. Nothing ships independently of a tag push.

### 2. Staged per channel: test → smoke → approval → prod

Each channel must have:

- A **staging target** (TestPyPI, a pre-release registry, etc.)
- **Smoke tests** that run automatically against the staging artifact
- An **approval gate** (GitHub Environment with required reviewers) before
  the production publish
- A **production publish** that only runs after the gate is approved

The pattern is the same for every channel, even if the tooling differs.

### 3. Version source of truth

`pyproject.toml` is the authoritative version. All other references
(`src/compose_lint/__init__.py`, extension `package.json`, etc.) must match
it. Use `scripts/bump-version.sh` to update all pre-release version files
atomically — do not edit them by hand.

The `marketplace-smoke.yml` action pin is a post-release step (the commit SHA
only exists once the tag is pushed). See `docs/RELEASING.md`.

### 4. Every artifact is signed and attested

| Channel         | Mechanism                         |
| --------------- | --------------------------------- |
| PyPI            | Sigstore OIDC + build attestation |
| Docker Hub      | cosign keyless (Sigstore OIDC)    |
| Future channels | Per-registry equivalent required  |

Signing is non-negotiable. A channel without signing is not ready to ship.

### 5. All publish jobs live in `publish.yml`

New channels are added as jobs in `.github/workflows/publish.yml`, not as
separate workflow files. This keeps the full release topology visible in one
place. Each new job must declare `needs: [<prior_channel>]` so channels
ship in a defined order.

## Current channels

| Channel    | Staging      | Smoke | Approval gate | Signed    |
| ---------- | ------------ | ----- | ------------- | --------- |
| PyPI       | TestPyPI     | yes   | `pypi` env    | Sigstore  |
| Docker Hub | local build  | yes   | none yet      | cosign    |

> **Known gap — Docker approval gate:** Docker currently has smoke tests but
> no approval gate before the production push. This will be addressed before
> additional channels are added.

## Adding a new channel

Every PR that introduces a new distribution channel must include:

- [ ] A job in `publish.yml` with `needs: [<prior_job>]`
- [ ] A staging target and smoke test job before the prod job
- [ ] A GitHub Environment with required reviewers for the prod job
- [ ] Signing/attestation for the published artifact
- [ ] An entry in `docs/RELEASING.md` covering the approval step
- [ ] An entry in the "Current channels" table above
