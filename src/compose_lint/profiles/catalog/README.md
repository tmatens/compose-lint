# Security profile catalog

One YAML document per image, conforming to
[`../schema/profile.schema.json`](../schema/profile.schema.json) (ADR-017).

Entries are **derived, not hand-authored.** A profile is produced by running
[container-sec-derive](https://github.com/tmatens/container-sec-derive) against a
live container (`--format compose-lint-profile`, ≥5-minute window, digest-pinned
image) and contributed via PR through the profile-validation workflow, which
appends `ci-smoke` to `validated_via`. See the contributor guide (forthcoming).

The match key is the canonical repository reference — files may be organized in
`registry/namespace/` subdirectories for readability, but the loader indexes each
document by its own `image` field, not by path.

Below-bar drafts (`status: exploratory`) live under `exploratory/` and are never
used for enrichment or conformance — review material only.

This directory ships empty: profiles come from real observation runs, so none are
committed until a derivation lands.
