# Security Expectations

This document tells you, the user of compose-lint, what to expect — and
what *not* to expect — from the tool in security terms. It is the
plain-English companion to [docs/ASSURANCE.md](ASSURANCE.md) (the
formal assurance case) and [.github/SECURITY.md](../.github/SECURITY.md)
(the vulnerability-reporting policy).

If you are evaluating whether to put compose-lint in a production
pipeline, this is the page to read.

## What compose-lint promises

1. **It will not execute the contents of the YAML you hand it.**
   compose-lint parses Compose and config files with `yaml.SafeLoader`
   only. There is no `yaml.load` path, no `eval`, no `exec`, and no
   subprocess invocation against parsed values. A malicious Compose file
   cannot get the linter to run code on your behalf.

2. **It will not connect to the network.** The product code performs no
   network I/O — no DNS, no HTTP, no telemetry. You can prove this: the
   documented hardened `docker run` recipe in
   [README.md](../README.md#running-with-full-hardening) sets
   `--network none`, and CI runs the full smoke battery under that flag
   set on every release.

3. **It will not modify your Compose files.** compose-lint only reads
   its inputs. There is no `--fix`, no rewrite mode, no in-place edit.
   (A future `--fix` mode would be additive and opt-in, never the
   default — see [docs/ROADMAP.md](ROADMAP.md).)

4. **Released artifacts are signed.** Every release ships:
   - PyPI wheel + sdist with PEP 740 trusted-publisher attestations and
     Sigstore bundles attached to the GitHub Release.
   - SLSA build provenance (`actions/attest-build-provenance`) per
     artifact.
   - SPDX SBOM attached to the GitHub Release.
   - Container manifest signed with cosign; SBOM and OpenVEX attested
     to the image manifest.
   - Verification commands and the OIDC identity to expect are in
     [.github/SECURITY.md](../.github/SECURITY.md) §"Supply Chain".

5. **The runtime image is minimal.** The Docker image runs on
   [distroless](https://github.com/GoogleContainerTools/distroless)
   `python3-debian13:nonroot` (no shell, no apt, UID 65532). pip
   binaries are stripped from the runtime venv; only `.dist-info`
   metadata is retained for SCA scanner attribution. See
   [ADR-009](adr/009-runtime-base-image.md).

6. **Tampered tags cannot publish.** `publish.yml` only runs on
   annotated, main-reachable tags whose SSH signature is verified
   against [`.github/allowed_signers`](../.github/allowed_signers). An
   attacker who pushed a malicious tag to the repo could not get it to
   ship.

## What compose-lint does NOT promise

1. **It is not a Compose schema validator.** A file that fails Compose
   schema validation may still be linted; an invalid Compose file may
   exit 2 (usage error) but compose-lint is not the right tool to tell
   you *why* it is invalid. Pair with
   [dclint](https://github.com/zavoloklom/docker-compose-linter).

2. **It is not an image-content scanner.** compose-lint does not pull
   the images your Compose file references, does not inspect their
   layers, and does not report CVEs in those images. Pair with
   [Trivy](https://github.com/aquasecurity/trivy) or
   [Docker Scout](https://www.docker.com/products/docker-scout/).

3. **It is not a Dockerfile linter.** compose-lint reads `compose.yaml`
   and `docker-compose.yml`, never `Dockerfile`. Pair with
   [Hadolint](https://github.com/hadolint/hadolint).

4. **It is not a runtime monitor.** compose-lint is a static analyzer.
   It cannot tell you what a running container is *actually* doing —
   only what its declared configuration *would* let it do.

5. **It is not exhaustive.** The 21 rules cover the misconfigurations
   that the OWASP Docker Security Cheat Sheet, CIS Docker Benchmark,
   and Docker official documentation ground (see
   [README.md](../README.md#rules) for the full list). Misconfigurations
   that none of those sources document, and that are not severe enough
   to be unmistakably wrong, are intentionally not flagged. The bar for
   adding a rule is documented in
   [CONTRIBUTING.md](../CONTRIBUTING.md) §"Rule requirements".

6. **It does not promise zero false positives or zero false
   negatives.** Every rule ships positive *and* negative tests
   including "hardened-but-unusual" fixtures, and the
   [corpus snapshot](../tests/corpus_snapshot.json.gz) regression-tests
   findings against ~1,500 real-world Compose files — but the threat
   model in [docs/ASSURANCE.md](ASSURANCE.md) acknowledges both
   classes as real risks. Report a false positive or false negative as
   a normal GitHub issue using the bug template.

7. **It does not maintain old releases.** Per
   [.github/SECURITY.md](../.github/SECURITY.md) §"Supported Versions",
   only the latest minor release receives security fixes. Pin to a
   recent version and bump on a regular cadence.

## When you should NOT rely on compose-lint alone

- **Defense-in-depth missing.** If compose-lint is the only static
  check in your pipeline, you have a blind spot. Pair it with a
  Dockerfile linter, an image scanner, and a Compose schema validator
  as listed above. Each tool covers a different layer.

- **Custom or proprietary Compose extensions.** compose-lint targets
  the upstream [Compose Specification](https://github.com/compose-spec/compose-spec).
  Vendor-specific `x-` extensions are skipped, not validated.

- **You need formal certification.** compose-lint does not claim
  conformance to any specific certification (FedRAMP, ISO 27001, SOC
  2). The supply-chain practices documented in
  [docs/ASSURANCE.md](ASSURANCE.md) are designed to support such an
  audit, but the certification itself is on you.

## How to verify these claims

- **Run the test suite.** `pytest` exercises every rule and the parser
  on positive, negative, and hardened-but-unusual fixtures. CI runs the
  same on Python 3.10–3.14 on every PR.
- **Run the corpus snapshot.** See
  [CONTRIBUTING.md](../CONTRIBUTING.md) §"Corpus snapshot" for the
  out-of-tree corpus. Findings against ~1,500 real Compose files are
  locked in `tests/corpus_snapshot.json.gz`; PR diffs show any drift.
- **Verify a release signature.** Commands and the expected OIDC
  identity are in [.github/SECURITY.md](../.github/SECURITY.md)
  §"Supply Chain".
- **Read the assurance case.** [docs/ASSURANCE.md](ASSURANCE.md) maps
  every claim above to the design choices and tooling that enforce it.

## Reporting a security issue with compose-lint itself

Use the private-vulnerability process in
[.github/SECURITY.md](../.github/SECURITY.md). Do not open public issues
for security findings. Acknowledgment SLA is 7 days.
