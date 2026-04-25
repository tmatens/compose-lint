# ADR-012: VEX Product Identifier and Author Allowlist

**Status:** Accepted

**Context:** compose-lint 0.5.1 shipped `.vex/compose-lint.openvex.json` declaring CVE-2025-8869 and CVE-2026-1703 as `not_affected` / `vulnerable_code_not_present` against the published container image, and wired `docker/scout-action`'s `vex-location` input on every step that scans the image (`scout-scan.yml`, `publish.yml`'s `docker-smoke`). After 0.5.1 shipped, Scout still flagged both CVEs and the post-merge code-scanning analysis kept alerts #82 and #83 open. Two independent failures were responsible.

**Decision:** Two changes.

1. **Product identifier registry alias.** The OpenVEX `products[].@id` uses `pkg:oci/compose-lint?repository_url=index.docker.io/composelint/compose-lint`, not `docker.io/...`. The Trivy / Scout / Grype canonical hostname for Docker Hub is `index.docker.io`; `docker.io` is widely accepted as a user-facing alias but is not what scanners normalise to internally for VEX product matching.
2. **`vex-author` override on every Scout step.** `docker scout cves` defaults `--vex-author` to `<.*@docker.com>` and silently drops statements signed by anyone outside that allowlist. Every `docker/scout-action` step that passes `vex-location` also passes `vex-author: <.*@gmail\.com>` so our maintainer-authored statements are honoured.

The product `@id` is digest-free so re-releases do not require editing the VEX file or running a substitution step in the publish pipeline. If a future scanner is observed to require digest qualification specifically (none in our tested set do), that decision can be revisited; the substitution would slot in between manifest-list creation and the `cosign attest` / release-asset upload steps in `publish.yml`.

---

## Why `index.docker.io` instead of `docker.io`

Local probing against `composelint/compose-lint:latest` (0.5.1, manifest digest `sha256:fdf35fc6…`):

- Trivy 0.70.0 with `--vex .vex/compose-lint.openvex.json` and `repository_url=docker.io/composelint/compose-lint` — both pip CVEs still listed.
- Trivy 0.70.0 with `repository_url=index.docker.io/composelint/compose-lint` — both pip CVEs suppressed, only the new CVE-2026-3219 (added in this same change) remains, and is also suppressed once its statement lands.

This matches anchore/grype#2818, which documents the same `docker.io` → `index.docker.io` alias gap as a Grype bug with a working workaround. Scout was not retested locally because the scout-cli container requires a Docker Hub login the development machine does not have; verification deferred to the next `scout-scan.yml` dispatch on `main`.

The `pkg:oci/<name>?repository_url=<registry>/<namespace>/<name>` form (with the image name appearing twice) follows the convention shown in the Trivy "VEX Attestation" docs (`pkg:oci/trivy?repository_url=ghcr.io/aquasecurity/trivy`). Other forms considered and rejected for v1:

- `pkg:docker/composelint/compose-lint?repository_url=index.docker.io` (per docker/scout-cli#199's example) — Trivy did not match this form against the image; would need a parallel `pkg:oci` entry to keep Trivy working, doubling the surface for no observed benefit.
- Multi-identifier products (multiple `products[]` entries on one statement, each with a different `@id`) — viable but unnecessary while one form is accepted by all tested scanners. Revisit if a scanner is observed to need a form the current entry does not cover.
- Digest-qualified PURLs — would require a release-time substitution step. Not adopted because the digest-free form works against Trivy and is what Scout's official docs example uses.

## Why the `vex-author` override

`docker scout cves --help` lists:

```
--vex-author strings   List of VEX statement authors to accept (default [<.*@docker.com>])
```

Our document is authored by `Todd Matens <tmatens@gmail.com>`. Without an override, Scout loads the document (the action logs `Loaded 1 VEX document`) and then drops every statement during the author check. The CLI default is undocumented in `docker/scout-action`'s `action.yaml` input schema — `vex-author` is exposed as an input but its default-allowlist behaviour is inherited silently from the underlying CLI.

The override is set on every scout-action step (`scout-scan.yml` gate, `scout-scan.yml` SARIF sweep, `publish.yml` docker-smoke). The pattern `<.*@gmail\.com>` mirrors the bracket-anchored shape of Scout's default and is intentionally a regex rather than a literal email so a future maintainer email under the same domain doesn't silently re-break suppression.

## Open Scout caveats

Two upstream Scout issues affect statement-level behaviour but do not change this ADR:

- **docker/scout-cli#199** — Scout 1.18.2+ does not always honour newer VEX statements that include subcomponents. Our document uses subcomponents on every statement (so the scanner pins the suppression to the specific pip version, not "any pip"). This is acceptable risk: when we change a statement we bump `version` and `timestamp` and accept that Scout may continue to apply the prior statement until its index refreshes. The post-fix `scout-scan.yml` run is the canary for this.
- **docker/scout-cli#207** — `docker scout cves --vex-location` historically had product-matching gaps for VEX statements scoped to the image rather than to nested components. Our statements scope to the image *with subcomponents*, which matches what felipecruz91/node-ip-vex (Docker's reference example) does and is the form Scout's "Create exceptions" docs page targets.

## References

- [OpenVEX Specification v0.2.0](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) — "list as many software identifiers as possible to help VEX processors when matching the product."
- [Trivy — VEX Attestation (OCI)](https://trivy.dev/latest/docs/supply-chain/vex/oci/) — canonical `pkg:oci/<name>?repository_url=<registry>/<namespace>/<name>` example.
- [Docker Scout — Create an exception using VEX](https://docs.docker.com/scout/how-tos/create-exceptions-vex/)
- [anchore/grype#2818](https://github.com/anchore/grype/issues/2818) — `docker.io` registry alias does not match; `index.docker.io` does.
- [docker/scout-cli#199](https://github.com/docker/scout-cli/issues/199) — VEX statements with subcomponents not honoured across updates.
- [docker/scout-cli#207](https://github.com/docker/scout-cli/issues/207) — `docker scout cves --vex-location` product-matching gaps.
