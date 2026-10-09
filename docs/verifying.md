# Verifying a compose-lint release

Every release is signed in CI without a long-lived key. The release workflow's GitHub OIDC token gets a short-lived [Sigstore](https://www.sigstore.dev/) certificate that names the workflow and the tag it ran for, and the signature is recorded in Sigstore's public transparency log. Verifying a release means checking that certificate, so pin both of these:

- **Identity:** `https://github.com/tmatens/compose-lint/.github/workflows/publish.yml@refs/tags/vX.Y.Z`
- **Issuer:** `https://token.actions.githubusercontent.com`

A check that only asks "is there a valid signature" proves nothing, since anyone can sign anything with their own identity.

## Docker image

With [cosign](https://github.com/sigstore/cosign) 3 (the signatures are stored as OCI referrers in the Sigstore bundle format):

```bash
VERSION=0.34.0
cosign verify \
  --certificate-identity "https://github.com/tmatens/compose-lint/.github/workflows/publish.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "composelint/compose-lint:${VERSION}"
```

Pin the exact tag rather than a pattern. A pattern accepts any release's signature, so it cannot tell when a version tag has been moved onto an older, legitimately signed image; the exact identity can. Then pin the verified digest in your Compose file or CI, as the [hardening walkthrough](hardening.md) shows.

To accept any release, for example when checking `latest`, anchor the pattern at both ends:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/tmatens/compose-lint/\.github/workflows/publish\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  composelint/compose-lint:latest
```

The image also carries an SPDX SBOM and an OpenVEX document, attested with the same identity. `cosign verify-attestation` needs `--type` to find them:

```bash
cosign verify-attestation --type spdxjson \
  --certificate-identity "https://github.com/tmatens/compose-lint/.github/workflows/publish.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "composelint/compose-lint:${VERSION}"
```

Use `--type openvex` for the VEX document.

## Python package

From 0.3.7 on, the wheel and sdist on PyPI are also attached to the [GitHub Release](https://github.com/tmatens/compose-lint/releases), each with a Sigstore bundle beside it. With [sigstore-python](https://github.com/sigstore/sigstore-python):

```bash
VERSION=0.34.0
pip download "compose-lint==${VERSION}" --no-deps --only-binary :all: -d .
gh release download "v${VERSION}" -R tmatens/compose-lint -p '*.whl.sigstore.json'
python -m sigstore verify identity \
  --cert-identity "https://github.com/tmatens/compose-lint/.github/workflows/publish.yml@refs/tags/v${VERSION}" \
  --cert-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle "compose_lint-${VERSION}-py3-none-any.whl.sigstore.json" \
  "compose_lint-${VERSION}-py3-none-any.whl"
```

From 0.4.1 on, the same files also carry SLSA build provenance, which the GitHub CLI verifies:

```bash
gh attestation verify "compose_lint-${VERSION}-py3-none-any.whl" \
  --repo tmatens/compose-lint \
  --signer-workflow tmatens/compose-lint/.github/workflows/publish.yml
```

Every release on PyPI, including the earliest, also has PyPI's own [PEP 740](https://peps.python.org/pep-0740/) attestations, shown under "Provenance" on the [project page](https://pypi.org/project/compose-lint/).

## What each release carries

Older releases predate some of these. Run against a release that lacks the artifact, a command fails without implying tampering: `cosign verify-attestation` reports "none of the attestations matched the predicate type", `gh attestation verify` returns HTTP 404, and `gh release download` finds no bundle.

| Releases | Image signing identity | Image SBOM | Image VEX | Wheel Sigstore bundle | SLSA provenance |
| --- | --- | --- | --- | --- | --- |
| 0.5.1 on | `publish.yml@refs/tags/vX.Y.Z` | yes | yes | yes | yes |
| 0.4.1 – 0.5.0 | `publish.yml@refs/tags/vX.Y.Z` | yes | no | yes | yes |
| 0.3.7 – 0.4.0 | `publish.yml@refs/tags/vX.Y.Z` | yes | no | yes | no |
| 0.3.6 | `publish.yml@refs/tags/v0.3.6` | yes | no | no | no |
| 0.3.4 | `publish-channel.yml@refs/tags/v0.3.4` | no | no | no | no |
| 0.3.3 | `docker-publish.yml@refs/tags/v0.3.3` | no | no | no | no |

0.3.3 and 0.3.4 were signed by workflows that have since been removed: 0.3.3 by the first Docker workflow, which `publish.yml` replaced, and 0.3.4 by a republish workflow. Verify them with the identity in the table; the any-release pattern above does not match them. A republish now runs inside `publish.yml` on the release tag, so it signs with the same identity as the release itself.

The 0.3.2 image was published and signed by the first Docker workflow, then removed from Docker Hub. 0.3.0, 0.3.1 and 0.3.5 never had an image: the Docker workflow did not yet exist for 0.3.0, and the other two publishes failed before pushing.
