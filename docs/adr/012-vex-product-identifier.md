# ADR-012: VEX Product Identifier and Author Allowlist

**Status:** Accepted (revised after PR #143's first attempt did not suppress on Scout)

**Context:** compose-lint 0.5.1 shipped `.vex/compose-lint.openvex.json` declaring CVE-2025-8869 and CVE-2026-1703 as `not_affected` / `vulnerable_code_not_present` against the published container image, and wired `docker/scout-action`'s `vex-location` input on every step that scans the image (`scout-scan.yml`, `publish.yml`'s `docker-smoke`). After 0.5.1 shipped, Scout still flagged both CVEs and the post-merge code-scanning analysis kept alerts #82 and #83 open. PR #143 made two changes (registry alias + author override). Trivy honoured the result locally; the post-merge `scout-scan.yml` dispatch on commit `5abd036` showed Scout still flagging all three pip CVEs despite logging `Loaded 1 VEX document`. This ADR captures the revised decision after that empirical failure.

**Decision:** Three changes.

1. **Registry alias.** OpenVEX `products[].@id` uses `repository_url=index.docker.io/composelint/compose-lint`, not `docker.io/...`. Trivy, Grype (anchore/grype#2818), and Scout all canonicalise Docker Hub to `index.docker.io` for VEX product matching. *(Unchanged from PR #143.)*
2. **Multiple product identifiers per statement.** Every statement carries two `products[]` entries: the `pkg:oci/...?repository_url=...` form (which Trivy and Grype accept) and a bare `pkg:docker/composelint/compose-lint` form (which Docker Scout's own "Create exceptions" docs example uses). OpenVEX explicitly invites this — "list as many software identifiers as possible to help VEX processors when matching the product." *(Added in this revision.)*
3. **Permissive `vex-author`.** Every `docker/scout-action` step that passes `vex-location` also passes `vex-author: .*`. The first attempt used `<.*@gmail\.com>` (mirroring Scout's default-allowlist shape `<.*@docker.com>`) and was silently dropped, suggesting Scout uses full-string regex match rather than substring. `.*` accepts any author and is safe because the document is also cosign-attested to the image manifest at publish time. *(Loosened in this revision.)*

The product `@id`s remain digest-free so re-releases do not require editing the VEX file or running a substitution step in the publish pipeline. If even the multi-identifier static form is observed to fail against Scout, the next escalation is digest qualification (`pkg:oci/compose-lint@sha256:<index-digest>?repository_url=...`); the substitution step would slot in between manifest-list creation and the `cosign attest` / release-asset upload steps in `publish.yml`. We prefer to avoid that complexity unless required.

---

## Why two PURL types instead of one

There is no single product-identifier convention for "an image on Docker Hub" that all attestation-aware scanners accept. The PURL spec defines two registered types for the same artifact and scanners disagree on which one (and which registry hostname) they normalise to:

- **`pkg:oci/<name>?repository_url=<registry>/<namespace>/<name>`** — registry-agnostic, modern PURL form. Trivy's "VEX Attestation" docs use this form (`pkg:oci/trivy?repository_url=ghcr.io/aquasecurity/trivy`); Trivy and Grype accept it. Tested locally.
- **`pkg:docker/<namespace>/<name>`** — Docker-specific legacy PURL form, no registry component (Docker Hub is implicit). Docker Scout's "Create exceptions" docs page uses this form (`pkg:docker/example/app@v1`). Pre-revision, Scout did not match against the `pkg:oci/` form alone in production.

Both are *registered* PURL types in the spec; both are valid. Shipping one identifier means picking a winner in a disagreement that has no winner. Shipping both costs ~12 lines of JSON and lets each scanner match against whatever form it normalises the scanned image to.

The `pkg:docker/` form intentionally omits a tag and a digest. A tag-qualified form (`pkg:docker/composelint/compose-lint:latest`) would suppress only against the `latest` tag, which is wrong — a digest-pinned consumer pulling the same image should still see the suppression. A digest-qualified form (`pkg:docker/composelint/compose-lint@sha256:<digest>`) would force release-time substitution. The bare form covers all tags and all digests of the named image.

## Why `index.docker.io` not `docker.io`

Local probing against `composelint/compose-lint:latest` (0.5.1, manifest digest `sha256:fdf35fc6…`):

- Trivy 0.70.0 with `repository_url=docker.io/composelint/compose-lint` — both pip CVEs still listed.
- Trivy 0.70.0 with `repository_url=index.docker.io/composelint/compose-lint` — pip CVEs suppressed.

This matches anchore/grype#2818, which documents the same `docker.io` → `index.docker.io` alias gap as a Grype bug with a working workaround. Scout exhibits the same behaviour empirically — `docker.io` form did not suppress before PR #143; `index.docker.io` form did not suppress *alone* but is retained because Trivy and Grype need it.

## Why the `vex-author` override is permissive

`docker scout cves --help` lists:

```
--vex-author strings   List of VEX statement authors to accept (default [<.*@docker.com>])
```

Our document is authored by `Todd Matens <tmatens@gmail.com>`. The first override (`<.*@gmail\.com>`, mirroring the bracket-anchored shape of Scout's default) was silently dropped — the post-merge dispatch of `scout-scan.yml` showed `Loaded 1 VEX document` followed by all three CVEs still flagged. The simplest hypothesis is that Scout's matcher is full-string rather than substring, so `<.*@gmail\.com>` only matches the bracketed-email portion of the author string, not the entire `Todd Matens <tmatens@gmail.com>`.

Rather than chase the exact regex shape (which Scout's behaviour is undocumented on), `vex-author: .*` accepts any author. This is acceptable because:

- The document on disk in CI comes from `actions/checkout` of the project repo, not from an arbitrary URL — there is no opportunity for an attacker-authored VEX file to reach the scout-action step.
- The same document is cosign-attested to the image manifest with predicate type `openvex` at release time, so external consumers verifying via attestation discovery have signature-level provenance.
- The default allowlist exists to filter VEX documents *Docker* did not author from being trusted by enterprise customers using Scout's hosted Hub workflow. That threat model does not apply to a project's own VEX document running against its own repo's CI.

## Base-image statements name no subcomponent (amendment 2026-11-24)

Docker Scout 1.28.0 began identifying the Debian release of the distroless base and reporting its packages' CVEs. Issue #1365 reviewed the ones Debian will not fix and added `not_affected` statements for 13 of them; a second review added 41 of the newer ones, on the same terms. The pip statements' shape, a bare `pkg:pypi/pip` subcomponent, does not carry over to a Debian package. One scan with each scanner, over a document that named the subcomponent a different way on each statement, gave:

| Subcomponent | Docker Scout 1.29.0 | Trivy 0.76.2 |
|---|---|---|
| none | suppressed | suppressed |
| source package with its exact version, `pkg:deb/debian/sqlite3@<version>?os_name=debian&os_version=13` | suppressed | not suppressed |
| source package with its version only, `pkg:deb/debian/openssl@<version>` | suppressed | CVE not reported |
| source package with qualifiers and no version | not suppressed | not suppressed |
| bare source package, `pkg:deb/debian/util-linux` | not suppressed | not suppressed |
| bare binary packages, `pkg:deb/debian/libkrb5-3` | not suppressed | suppressed |

Scout matches a Debian subcomponent only when it carries the version, and by source package name. Trivy matches by binary package name. A version-pinned statement stops matching when Debian updates the package, which for glibc, OpenSSL and krb5 is every few weeks, so it would need an edit on most base-image bumps, and those bumps merge themselves.

**Decision:** a base-image statement lists the two product identifiers and no `subcomponents`. It then reads "this image is not affected by this CVE", which is the claim being made, and both scanners honour it. Each of these CVE identifiers belongs to one upstream project, so leaving the package out cannot suppress a finding in another one.

**The cost, and what pays for it.** A version-pinned statement is scoped to the images that carry the package version that was checked, and lapses by itself when that changes. A statement with no subcomponent and no digest applies to every published tag, past and future, and keeps applying after the base image or compose-lint changes, whether or not it is still true. Two things answer that:

- **Future images.** `tests/smoke/assert_vex_claims.py` runs inside the built image in the PR and release Docker smokes. It runs compose-lint over its main paths and then checks the facts the impact statements rely on: which modules were loaded, which shared objects are mapped and what each imports from libc, which files the image ships, and who owns the directories Python searches at startup. A base digest bump changes the Dockerfile and so runs it. `tests/test_vex_claims.py` holds the script's `GUARDED` list equal to the document's base-image statements, so a statement cannot be added without a check.
- **Past images.** Before the statements were written, the same facts were checked against the base image of every release built on distroless (0.3.6 onward, both platforms, from the exported filesystem), and the source facts against every release tag. The two Alpine-based tags still published, 0.3.3 and 0.3.4, predate the distroless base; they were checked separately and the result is recorded on #1365.

The check fails open where the pinned form fails closed: a fact a statement relies on that the script does not test would go unnoticed. So a statement's impact statement and its check are written together, and the impact statement says only what was checked.

Three other CVEs from the same review (CVE-2019-1010022, CVE-2019-1010024 and CVE-2019-1010025) describe weaker glibc hardening, not a code path that is absent or unreached. No OpenVEX justification is true of them, so they have no statement.

## Open Scout caveats

Two upstream Scout issues affect statement-level behaviour but do not change this ADR:

- **docker/scout-cli#199** — Scout 1.18.2+ does not always honour newer VEX statements that include subcomponents. Our document uses subcomponents on every pip statement (so the scanner pins the suppression to pip, not to the image as a whole); the base-image statements carry none, for the reasons in the amendment above. When we change a statement we bump `version` and `timestamp` and accept that Scout may continue to apply the prior statement until its index refreshes. The post-fix `scout-scan.yml` run is the canary for this.
- **docker/scout-cli#207** — `docker scout cves --vex-location` historically had product-matching gaps for VEX statements scoped to the image rather than to nested components. Our statements scope to the image *with subcomponents*; the multi-identifier change is an explicit response to this issue.

## References

- [OpenVEX Specification v0.2.0](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md) — "list as many software identifiers as possible to help VEX processors when matching the product."
- [Trivy — VEX Attestation (OCI)](https://trivy.dev/latest/docs/supply-chain/vex/oci/) — `pkg:oci/<name>?repository_url=<registry>/<namespace>/<name>` example.
- [Docker Scout — Create an exception using VEX](https://docs.docker.com/scout/how-tos/create-exceptions-vex/) — `pkg:docker/example/app@v1` example.
- [PURL spec — `pkg:oci` and `pkg:docker` types](https://github.com/package-url/purl-spec) — two registered types for the same artifact class.
- [anchore/grype#2818](https://github.com/anchore/grype/issues/2818) — `docker.io` registry alias does not match; `index.docker.io` does.
- [docker/scout-cli#199](https://github.com/docker/scout-cli/issues/199) — VEX statements with subcomponents not honoured across updates.
- [docker/scout-cli#207](https://github.com/docker/scout-cli/issues/207) — `docker scout cves --vex-location` product-matching gaps.
- PR #143 — first attempt (registry alias + bracket-anchored author regex). Verified Scout still flagged all three CVEs on the post-merge dispatch (run `24921123739`).
