# Security Policy

For what compose-lint will and will not protect you against, see
[docs/SECURITY-EXPECTATIONS.md](../docs/SECURITY-EXPECTATIONS.md). For
the full assurance case (threat model, trust boundaries, mitigations),
see [docs/ASSURANCE.md](../docs/ASSURANCE.md).

## Supported Versions

compose-lint follows semantic versioning. Only the latest minor release
receives security fixes.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use GitHub's private vulnerability reporting:

1. Go to <https://github.com/tmatens/compose-lint/security/advisories/new>
2. Submit a report with reproduction steps and impact

You should receive an acknowledgement within 7 days. If the report is valid, a fix
will be coordinated and released, and the advisory will be published with credit
unless you request otherwise.

## What counts as a vulnerability

A defect is a vulnerability, and gets a published GitHub security
advisory, when all three of these hold:

1. **Someone with less trust than you can cause it.** That means an
   author of content compose-lint reads (a pull request contributor, the
   author of a template or included file, whoever names files and
   directories, env files, a policy file arriving in a pull request) or
   someone in the distribution chain. This includes their data arriving
   through an input compose-lint documents, such as a list of changed
   files passed to the Action's `files:`. It does not mean you, the
   author of the workflow that runs compose-lint, or the project's
   maintainers. The harm must not depend on someone approving content
   that is visible in the pull request. If a reviewer reading the diff
   would see everything the attack needs, compose-lint missing it is a
   false negative, not a vulnerability.
2. **It breaks one of the security properties** P0–P7 in
   [docs/SECURITY-EXPECTATIONS.md](../docs/SECURITY-EXPECTATIONS.md#security-properties):
   no execution, read confinement, output confinement, write safety,
   output integrity, verdict integrity, policy integrity, artifact
   integrity.
3. **It shipped in a release:** a version tag (which the GitHub Action
   and the pre-commit hook resolve), a PyPI release, or a published image
   tag. The `main` branch is not a release. A defect introduced and fixed
   between two releases gets no advisory.

How Docker Compose handles the same input is recorded in the advisory
but doesn't decide the verdict. compose-lint runs where Compose doesn't —
on untrusted pull requests, before anything is deployed — so an input
Compose would reject can still be a compose-lint vulnerability.

This applies however the defect was found (an outside report, a
maintainer's own review, an automated audit) and whether or not it has
already been fixed.

## Not vulnerabilities

Report these as normal issues:

- **False negatives.** compose-lint read and graded the input and missed a
  finding, including with a file crafted to be missed, or one it models
  differently from Compose. It does not promise complete detection.
- **False positives,** and findings against the intentionally insecure
  fixtures in `tests/compose_files/`.
- **Anything a careful reviewer would see.** A pull request whose
  dangerous content, and whatever makes compose-lint miss it, are all
  visible in the diff.
- **A crash confined to the job that ran it.**
- **Resource exhaustion,** whatever its size or cause. A small input
  that makes compose-lint use too much memory or time is a bug; report
  it as one. Isolating and limiting the machines that run untrusted pull
  requests is the operator's job, and in a `pull_request` workflow the
  pull request's author can already run code on that machine.
- **Invisible or control characters in a pull request,** and what they
  make compose-lint's output look like, where the verdict stays
  accurate. Detecting hidden Unicode in contributions is the
  repository's job (GitHub's hidden-character warning, a pre-commit
  check). Output that a CI system *executes*, such as a workflow
  command, is still in scope under P4.
- **A limitation the documentation disclosed** for the version in
  question. Where shipped texts disagree (the README, the docs site,
  `action.yml`, `--help`), the stronger promise is the one judged, so a
  limitation stated in one place and contradicted by a promise in
  another is not disclosed.
- **A vulnerability in a dependency or the base image,** unless
  compose-lint makes it reachable and you can't fix it by updating the
  dependency yourself.
- **The project's own CI and development tooling,** unless a shipped
  artifact or a release credential could have been affected (P7).
- **Anything that needs one of the trusted parties in point 1:** the
  user, the workflow author, or a maintainer.

## How advisories are published

- **Severity** is CVSS 4.0, scored for the common configuration.
  Conditions needed for the worst case go in `AT` and are named in the
  text, and harm to the systems that consume compose-lint's output (the
  CI runner, its log, Code Scanning) is scored as subsequent-system
  impact. The severity label follows the score; where a maintainer
  overrides it, the advisory says why.
- **A false result that leaves a visible trace** in the pull request is
  scored as low integrity impact (`VI:L`): the verdict is wrong, but
  nothing deploys unless someone merges a change they could see. High
  integrity impact is for a false result that leaves no visible trace.
  `AT:P` marks only setups outside the ordinary way the affected surface
  is used; running the hook or the Action over pull-request files is the
  ordinary way.
- **Surfaces** are listed separately: the `compose-lint` package, the
  `tmatens/compose-lint` Action and pre-commit hook (both resolve the
  repository's version tags, and are listed under the `actions`
  ecosystem), and the `composelint/compose-lint` image. Each affected
  range is confirmed by reproducing the defect on the last affected
  release and its absence on the first fixed one.
- **Every affected version is listed,** even though only the latest minor
  release receives fixes.
- **A CVE is requested** for every advisory. Requesting one publishes
  nothing.
- **Publication follows the fixed release,** once its package, image and
  Action tag are live.
- **Reporters are credited** unless they ask not to be. Defects found by
  the maintainers say so.

Each `### Security` entry in [CHANGELOG.md](../CHANGELOG.md) ends with
either the advisory it fixes or `No advisory:` and the reason, so every
security fix records the decision.

## Supply Chain

- PyPI releases use [Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
  via GitHub Actions OIDC. No long-lived API tokens exist.
- Releases include [Sigstore build attestations](https://docs.pypi.org/attestations/).
  Verify with `pip install compose-lint --require-hashes` plus the published
  attestation.
- Dependencies are kept current by Renovate. CodeQL and OpenSSF Scorecard run
  on every push and weekly.
