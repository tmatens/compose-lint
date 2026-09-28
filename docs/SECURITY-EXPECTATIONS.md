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

3. **It will not modify your Compose files unless you ask.** `check`
   (the default command) only reads its inputs. The `fix` command is
   dry-run by default — it prints a unified diff and writes nothing;
   only `fix --apply` rewrites in place, via an atomic swap that
   preserves the read, write and execute bits (setuid, setgid and sticky
   are dropped rather than handed to the new inode). It applies only mechanically unambiguous
   edits, never weakens a suppressed finding, and re-parses and re-lints
   every change before writing. That guarantee covers the *edit*, not
   the *outcome*: a fix can still change how your stack behaves, and
   every such edit is labelled `⚠ behavior-changing` in the diff rather
   than withheld — see [docs/ROADMAP.md](ROADMAP.md) and the Fixing
   findings section of the README.

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

## Security properties

The promises above are the headline. These eight properties are the
precise version, and they define what counts as a vulnerability in
compose-lint: a defect is a vulnerability when it breaks one of them, can
be triggered by someone with less trust than you, and shipped in a
release (see [.github/SECURITY.md](../.github/SECURITY.md) §"What counts
as a vulnerability"). "Content" below means anything compose-lint reads
from the project: Compose files, env files, `.compose-lint.yml`, and the
names of files and directories.

| | Property | Example of a break | Not a break |
|---|---|---|---|
| **P0** | **No execution.** Content never causes code to run. | A YAML tag that constructs a Python object. | A crash on malformed YAML. |
| **P1** | **Read confinement.** The contents of a file outside the project never reach compose-lint's output, whatever a path says or resolves to. | A committed `.env` symlinked to `/proc/self/environ`, quoting the CI job's environment into findings (GHSA-6wcv-rj3c-mhv3). | A finding that quotes a path the Compose file itself wrote, such as a bind source. |
| **P2** | **Output confinement.** Data never lands in an output more exposed than where it came from, and a value is not quoted where its name would do. | A secret from an uncommitted, CI-generated env file quoted into SARIF that is uploaded to Code Scanning. | A finding quoting a non-secret value written in the Compose file itself. |
| **P3** | **Write safety.** `fix --apply` and `init` never write outside the file you asked for, and never change it beyond the fixes they report. A security setting removed or changed, or a new finding, that the reported fixes do not account for is a break whether or not a diff displayed it. | A reported fix to one service that also changes another service's security settings without reporting it. | A fix that mangles formatting or comments without touching a security setting. |
| **P4** | **Output integrity.** Content can't issue commands to whatever consumes the output: terminals, SARIF viewers, and the CI systems the documentation or changelog names (GitHub Actions and Azure Pipelines). | A service name that the GitHub Actions runner executes as a workflow command (GHSA-6f4g-xm8v-pgv6). | Garbled or misleading output from invisible or control characters, where the verdict stays accurate. Command syntax of a CI system neither names. |
| **P5** | **Verdict integrity.** The exit code and SARIF status accurately report what was graded, and anything that couldn't be read or graded fails closed. No claim is made that grading was complete. | SARIF recording a run as successful when a Compose file failed to parse. | A SARIF write failure that turns the step red. Any false negative. |
| **P6** | **Policy integrity.** Policy and suppressions come only from documented locations, and the policy in effect is the one a reviewer sees in the diff. | Suppressions taken from a comment inside the Compose file, a place the documentation doesn't list. | A pull request adding a visible suppression that reviewers approve. |
| **P7** | **Artifact integrity.** What you install was built by the release pipeline from signed `main`, so no one outside the maintainers can get an artifact published under the project's name. | A release path that publishes from a tag nobody signed. | A maintainer shipping a buggy release, or a newer release reaching an unpinned install. A CVE in a dependency. |

**False negatives are not vulnerabilities.** A false negative is the tool
reading and grading its input and missing a finding. That includes a
rule's check being incomplete, and an input that compose-lint models
differently from how Compose deploys it, even when the input was crafted
to be missed. Report them as ordinary bugs. What *is* in scope is the
tool reporting success over something it did not read or grade (P5), or
following a policy it should not have (P6).

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

5. **It is not exhaustive.** The 27 rules cover the misconfigurations
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
   a normal GitHub issue using the bug template, including one reached
   with a deliberately crafted file (see §"Security properties").

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
  same on Python 3.11–3.14 on every PR.
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
